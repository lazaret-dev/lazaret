// Worker threads for the CLI's per-file work (0.1.8): each worker runs its
// own instance of the native engine (lib/native.js; the module compiled once,
// here, and handed to every worker) and answers tasks — a file's scan, a
// dependency file's import-time and agent checks, the cross-file follower —
// one at a time, as the main thread would. The main thread hands out the
// tasks (two per worker at a time, the next as each answer comes) and takes
// the answers back in the order it asked, so a scan's findings and their
// order are the same with workers or without.
//
// `run()` is synchronous, so the main thread waits for answers rather than
// returning to the event loop: each worker posts its answer on its own
// MessagePort and then bumps a shared counter, on which the main thread
// waits (Atomics.wait) before reading the ports (receiveMessageOnPort). A
// task whose answer does not come (a worker that died: out of memory) is
// answered by the main thread itself after STALL_MS without any answer, and
// every task when no worker answers within STARTUP_MS of the first (workers
// that did not start); a worker that could not start (its engine does not
// answer) sends its tasks back at once, for the main thread to run.
//
// LAZARET_THREADS: how many workers (1: none); by default up to 8, one per
// core, and only for a scan with enough to read besides its largest file
// (MIN_CHARS characters): starting a worker costs about what scanning a few
// files does, and no number of threads makes one file's scan shorter.

import { Worker, MessageChannel, receiveMessageOnPort } from "node:worker_threads";
import { availableParallelism } from "node:os";
import { wasmModule, workBudgetSteps } from "./lib/native.js";
import { REDACT } from "./lib/redact.js";
import { scanTimeBudget } from "./scanner/scan.js";

export const MAX_THREADS = 8;
export const MIN_CHARS = 1_000_000;          // what a scan reads besides its largest file before it starts workers
const PER_WORKER = 2;                        // tasks a worker holds at once
const STALL_MS = 120_000;                    // no answer from any worker for this long: the main thread finishes
const STARTUP_MS = 15_000;                   // nor a first answer for this long (the workers could not start)

/**
 * The workers a scan should use: LAZARET_THREADS when it is set (a number,
 * 1 or less: none), else one per core (at most MAX_THREADS) for a scan with
 * at least MIN_CHARS characters to read besides its largest file (`total`
 * characters, `largest` of them in one file: a scan one file makes most of
 * takes that file's time on any number of threads). 0 or 1: none.
 */
export function threadsFor(env, total, largest = 0) {
  const set = env && env.LAZARET_THREADS !== undefined && String(env.LAZARET_THREADS).trim() !== "";
  if (set) {
    const n = Number.parseInt(String(env.LAZARET_THREADS), 10);
    return Number.isFinite(n) && n > 1 ? Math.min(n, 64) : 1;
  }
  if (total - largest < MIN_CHARS) return 1;
  let cores = 1;
  try { cores = availableParallelism(); } catch { /* an old node: one */ }
  return Math.max(1, Math.min(MAX_THREADS, cores));
}

export class Pool {
  /**
   * `n` workers, with this thread's scan settings (redaction, time and work
   * budgets), each running `module` (the compiled engine: this thread's).
   */
  constructor(n, module = wasmModule()) {
    this.signal = new Int32Array(new SharedArrayBuffer(4));
    this.workers = [];
    this.closed = false;
    this.started = false;                    // (a worker has answered)
    const config = { redact: REDACT.on, timeBudgetMs: scanTimeBudget(), workBudget: workBudgetSteps() };
    for (let k = 0; k < n; k++) {
      const { port1, port2 } = new MessageChannel();
      const worker = new Worker(new URL("./pool-worker.js", import.meta.url), {
        workerData: { signal: this.signal, port: port2, module, config }, transferList: [port2],
      });
      worker.on("error", () => {});          // (a worker that fails: its tasks are run here, see map)
      worker.unref();                        // (the pool never keeps the process alive)
      this.workers.push({ worker, port: port1, unable: false });
    }
  }

  /**
   * Answers to `tasks` ([kind, args], see pool-worker.js), in order: {ok:
   * true, value} or {ok: false, error: {name, message}}; `undefined` for a
   * task no worker answered (stalled, or sent back by a worker that could
   * not start).
   */
  map(tasks) {
    const answers = new Array(tasks.length);
    if (this.closed) return answers;
    let next = 0, done = 0;
    const held = this.workers.map(() => 0);
    const send = (w) => {
      while (!this.workers[w].unable && held[w] < PER_WORKER && next < tasks.length) {
        const id = next++;
        held[w]++;
        this.workers[w].port.postMessage({ id, kind: tasks[id][0], args: tasks[id][1] });
      }
    };
    this.workers.forEach((_, w) => send(w));
    let last = Date.now();
    while (done < tasks.length && !this.closed) {
      if (this.workers.every((w) => w.unable)) break;          // (no worker can answer: the caller runs the rest)
      const seen = Atomics.load(this.signal, 0);
      let got = false;
      for (let w = 0; w < this.workers.length; w++) {
        let m;
        while ((m = receiveMessageOnPort(this.workers[w].port)) !== undefined) {
          const a = m.message;
          done++;
          held[w]--;
          got = true;
          if (a.unable) this.workers[w].unable = true;          // (left unanswered: the caller runs it)
          else answers[a.id] = a;
        }
        send(w);
      }
      if (got) {
        last = Date.now();
        this.started = true;
        continue;
      }
      if (Date.now() - last > (this.started ? STALL_MS : STARTUP_MS)) {
        this.close();                        // (a worker died: the caller answers what is left)
        break;
      }
      Atomics.wait(this.signal, 0, seen, 1000);
    }
    return answers;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    for (const { worker, port } of this.workers) {
      port.close();
      worker.terminate().catch(() => {});
    }
  }
}

/**
 * Each task's value, in order: a worker's answer, or `local(task)` run here
 * for one no worker answered. A task that threw (here or in a worker) gives
 * `onError(task, error)`.
 */
export function mapTasks(pool, tasks, local, onError) {
  const answers = pool ? pool.map(tasks) : new Array(tasks.length);
  return tasks.map((task, k) => {
    const a = answers[k];
    if (a === undefined) {
      try { return local(task); } catch (e) { return onError(task, e); }
    }
    return a.ok ? a.value : onError(task, a.error);
  });
}
