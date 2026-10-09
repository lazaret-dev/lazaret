// What npm installs from a package tarball: pacote's extraction (npm's lib/fetcher.js, #tarxOptions), with the
// node-tar that npm itself bundles. One JSON line in per tarball ({"path": FILE}), one JSON line out:
// {"ok": bool, "error": message or null, "files": [[path, sha256, size], ...], "warnings": [[code, message], ...]}.
// Links are dropped and a .gitignore is written as .npmignore unless one was seen, as pacote does; the first
// path part is stripped (strip: 1). LAZARET_NPM_DIR names npm's folder (default: beside this node's binary).
'use strict'
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const readline = require('readline')

function npmDir () {
  if (process.env.LAZARET_NPM_DIR) return process.env.LAZARET_NPM_DIR
  const prefix = path.dirname(path.dirname(process.execPath))
  for (const dir of [path.join(prefix, 'lib', 'node_modules', 'npm'), path.join(path.dirname(process.execPath), 'node_modules', 'npm')]) {
    if (fs.existsSync(path.join(dir, 'node_modules', 'tar'))) return dir
  }
  throw new Error('npm\'s folder not found: set LAZARET_NPM_DIR')
}

const tar = require(path.join(npmDir(), 'node_modules', 'tar'))

function options (cwd, warnings) {
  const sawIgnores = new Set()
  return {
    cwd,
    noChmod: true,
    noMtime: true,
    filter: (name, entry) => {
      if (/Link$/.test(entry.type)) return false
      if (/File$/.test(entry.type)) {
        const base = path.basename(entry.path)
        if (base === '.npmignore') {
          sawIgnores.add(entry.path)
        } else if (base === '.gitignore') {
          const ni = entry.path.replace(/\.gitignore$/, '.npmignore')
          if (sawIgnores.has(ni)) return false
          entry.path = ni
        }
        return true
      }
    },
    strip: 1,
    onwarn: (code, msg) => { warnings.push([String(code), String(msg)]) },
    umask: 0o022,
    preserveOwner: false
  }
}

function walk (root, dir, out) {
  for (const name of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, name)
    const st = fs.lstatSync(full)
    if (st.isDirectory()) walk(root, full, out)
    else if (st.isFile()) {
      const data = fs.readFileSync(full)
      out.push([path.relative(root, full).split(path.sep).join('/'), crypto.createHash('sha256').update(data).digest('hex'), data.length])
    } else out.push([path.relative(root, full).split(path.sep).join('/'), 'other', 0])
  }
}

function extract (file) {
  return new Promise((resolve) => {
    const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'lz-npm-x-'))
    const warnings = []
    let done = false
    const finish = (error) => {
      if (done) return
      done = true
      const files = []
      try { walk(dest, dest, files) } catch (e) { error = error || String(e) }
      fs.rmSync(dest, { recursive: true, force: true })
      resolve({ ok: !error, error: error || null, files, warnings })
    }
    const extractor = tar.x(options(dest, warnings))
    extractor.on('end', () => finish(null))
    extractor.on('error', (er) => finish(String(er && er.message || er)))
    const input = fs.createReadStream(file)
    input.on('error', (er) => finish(String(er.message)))
    input.pipe(extractor)
  })
}

const rl = readline.createInterface({ input: process.stdin })
const queue = []
let busy = false
async function drain () {
  if (busy) return
  busy = true
  while (queue.length) {
    const line = queue.shift()
    let answer
    try { answer = await extract(JSON.parse(line).path) } catch (e) { answer = { ok: false, error: 'harness: ' + e, files: [], warnings: [] } }
    process.stdout.write(JSON.stringify(answer) + '\n')
  }
  busy = false
}
rl.on('line', (line) => { if (line.trim()) { queue.push(line); drain() } })
