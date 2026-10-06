//! A TCP socket for async code, without an event loop: each read and write runs on the worker
//! pool. Slower than a reactor (one thread hand-off per operation) but dependency-free and
//! executor-independent.

use super::io::{AsyncRead, AsyncWrite};
use super::pool::{BlockingTask, Pool};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Largest piece written or read by one worker job.
const CHUNK: usize = 64 * 1024;

pub(crate) fn deadline_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the request's total time limit was exceeded")
}

/// A TCP stream whose socket timeouts never reach past an overall deadline. Reads and writes
/// take `&self` (as `&TcpStream` allows), so a read and a write can run on different threads.
#[derive(Debug)]
pub(crate) struct Io {
    pub(crate) tcp: TcpStream,
    /// Limit for one read or write; only applied here when there is a deadline (otherwise the
    /// socket's own timeouts, set when it was connected, are in force).
    pub(crate) timeout: Duration,
    pub(crate) deadline: Option<Instant>,
}

impl Io {
    /// Arms the socket timeout for the next operation: the per-operation limit, shortened to
    /// the time left before the deadline.
    fn arm(&self, read: bool) -> io::Result<()> {
        let Some(deadline) = self.deadline else { return Ok(()) };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(deadline_error());
        }
        let t = Some(left.min(self.timeout));
        if read {
            self.tcp.set_read_timeout(t)
        } else {
            self.tcp.set_write_timeout(t)
        }
    }

    /// A timeout that happened because the deadline passed is reported as such.
    fn expired(&self, e: io::Error) -> io::Error {
        let timed_out = matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut);
        match self.deadline {
            Some(d) if timed_out && Instant::now() >= d => deadline_error(),
            _ => e,
        }
    }

    /// Applies the limits of the next request to a connection that has been waiting in a pool: the
    /// per-operation timeout on the socket and the new overall deadline.
    pub(crate) fn rearm(&mut self, timeout: Duration, deadline: Option<Instant>) -> io::Result<()> {
        self.timeout = timeout;
        self.deadline = deadline;
        self.tcp.set_read_timeout(Some(timeout))?;
        self.tcp.set_write_timeout(Some(timeout))
    }

    /// True if the peer has neither hung up nor sent anything: what a connection that is waiting
    /// for the next request looks like. (A closed peer reads as end of file, and anything else
    /// that is waiting, such as a TLS alert, means the connection is not to be trusted with a
    /// request.) The socket is polled without blocking and put back as it was.
    pub(crate) fn peer_quiet(&self) -> bool {
        if self.tcp.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let quiet = matches!(self.tcp.peek(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
        quiet && self.tcp.set_nonblocking(false).is_ok()
    }

    pub(crate) fn read_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(true)?;
        (&self.tcp).read(buf).map_err(|e| self.expired(e))
    }

    pub(crate) fn write_ref(&self, buf: &[u8]) -> io::Result<usize> {
        self.arm(false)?;
        (&self.tcp).write(buf).map_err(|e| self.expired(e))
    }
}

impl Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_ref(buf)
    }
}

impl Write for Io {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_ref(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

fn task_error(e: super::pool::TaskError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

/// [`AsyncRead`] + [`AsyncWrite`] over a blocking [`TcpStream`], with every read and write run
/// on a [`Pool`]. It works with any executor. Reads ask the socket for no more than the caller's
/// buffer holds, so nothing is read ahead of what was asked for. Writes are accepted at once into
/// a buffer and sent in the background, like a socket's send buffer: `poll_flush` waits for them
/// and reports any error.
///
/// Set read and write timeouts on the `TcpStream` before wrapping it; they are enforced by the
/// blocking calls.
pub struct ThreadedStream {
    io: Arc<Io>,
    pool: Pool,
    reading: Option<BlockingTask<io::Result<Vec<u8>>>>,
    /// Received but not yet handed out: `left[left_pos..]`.
    left: Vec<u8>,
    left_pos: usize,
    writing: Option<BlockingTask<io::Result<()>>>,
}

impl ThreadedStream {
    pub fn new(tcp: TcpStream, pool: Pool) -> ThreadedStream {
        ThreadedStream::from_io(Io { tcp, timeout: Duration::from_secs(u64::MAX / 4), deadline: None }, pool)
    }

    pub(crate) fn from_io(io: Io, pool: Pool) -> ThreadedStream {
        ThreadedStream { io: Arc::new(io), pool, reading: None, left: Vec::new(), left_pos: 0, writing: None }
    }

    /// The underlying socket.
    pub fn get_ref(&self) -> &TcpStream {
        &self.io.tcp
    }

    /// Applies the limits of the next request to a connection that has been waiting in a pool.
    /// False if the stream is busy (a read or write is still running), which makes it unfit for reuse.
    pub(crate) fn rearm(&mut self, timeout: Duration, deadline: Option<Instant>) -> bool {
        self.reading.is_none() && self.writing.is_none() && Arc::get_mut(&mut self.io).map_or(false, |io| io.rearm(timeout, deadline).is_ok())
    }

    /// True if nothing is in flight or unread here and the peer has neither hung up nor sent
    /// anything: the state of a connection that is waiting for the next request.
    pub(crate) fn peer_quiet(&self) -> bool {
        self.reading.is_none() && self.writing.is_none() && self.left_pos >= self.left.len() && self.io.peer_quiet()
    }
}

impl AsyncRead for ThreadedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.left_pos < this.left.len() {
                let n = (this.left.len() - this.left_pos).min(buf.len());
                buf[..n].copy_from_slice(&this.left[this.left_pos..this.left_pos + n]);
                this.left_pos += n;
                return Poll::Ready(Ok(n));
            }
            let task = match &mut this.reading {
                Some(t) => t,
                None => {
                    let io = this.io.clone();
                    let len = buf.len().min(CHUNK);
                    this.reading = Some(this.pool.spawn_blocking(move || {
                        let mut v = vec![0u8; len];
                        loop {
                            match io.read_ref(&mut v) {
                                Ok(n) => {
                                    v.truncate(n);
                                    return Ok(v);
                                }
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }));
                    this.reading.as_mut().expect("just set")
                }
            };
            let done = match Pin::new(task).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            };
            this.reading = None;
            let data = done.map_err(task_error)??;
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.left = data;
            this.left_pos = 0;
        }
    }
}

use std::future::Future;

impl ThreadedStream {
    /// Waits for the write in flight, if any.
    fn poll_writing(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(task) = &mut self.writing {
            let done = match Pin::new(task).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            };
            self.writing = None;
            done.map_err(task_error)??;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ThreadedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // one write job at a time: the next chunk is accepted when the last one has gone out
        match this.poll_writing(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let n = buf.len().min(CHUNK);
        let data = buf[..n].to_vec();
        let io = this.io.clone();
        this.writing = Some(this.pool.spawn_blocking(move || {
            let mut rest = &data[..];
            while !rest.is_empty() {
                match io.write_ref(rest) {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "the socket accepted no bytes")),
                    Ok(k) => rest = &rest[k..],
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_writing(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_writing(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match self.io.tcp.shutdown(Shutdown::Write) {
            // the peer may already be gone
            Err(e) if e.kind() != io::ErrorKind::NotConnected => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{block_on, AsyncReadExt, AsyncWriteExt};
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    #[test]
    fn echo_over_the_pool() {
        let (client, mut server) = pair();
        let echo = thread::spawn(move || {
            let mut buf = Vec::new();
            server.read_to_end(&mut buf).unwrap();
            server.write_all(&buf).unwrap();
        });
        let mut s = ThreadedStream::new(client, Pool::new(2));
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let got = block_on(async {
            s.write_all(&payload).await?;
            s.close().await?; // shutdown(Write): the echo side sees EOF
            let mut back = Vec::new();
            s.read_to_end(&mut back).await?;
            Ok::<_, io::Error>(back)
        })
        .unwrap();
        assert!(got == payload);
        echo.join().unwrap();
    }

    #[test]
    fn reads_never_ask_for_more_than_the_caller_wants() {
        let (client, mut server) = pair();
        server.write_all(b"0123456789").unwrap();
        let mut s = ThreadedStream::new(client, Pool::new(1));
        let mut three = [0u8; 3];
        block_on(s.read_exact(&mut three)).unwrap();
        assert_eq!(&three, b"012");
        // the other seven bytes were not pulled into a job's buffer: they are still on the socket
        let mut peek = [0u8; 16];
        s.get_ref().set_nonblocking(true).unwrap();
        let n = s.get_ref().peek(&mut peek).unwrap();
        assert_eq!(&peek[..n], b"3456789");
    }

    #[test]
    fn a_failed_write_is_reported_by_flush() {
        let (client, server) = pair();
        drop(server);
        let mut s = ThreadedStream::new(client, Pool::new(1));
        let big = vec![0u8; 8 * 1024 * 1024];
        // the peer is gone: the background write fails, and the error comes back from a later call
        let res = block_on(async {
            s.write_all(&big).await?;
            s.flush().await
        });
        assert!(res.is_err());
    }

    #[test]
    fn eof_reads_zero() {
        let (client, server) = pair();
        drop(server);
        let mut s = ThreadedStream::new(client, Pool::new(1));
        let mut buf = [0u8; 4];
        assert_eq!(block_on(s.read(&mut buf)).unwrap(), 0);
    }
}
