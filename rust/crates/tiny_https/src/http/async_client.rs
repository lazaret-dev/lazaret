//! The HTTP client for async code: the same requests, redirects, proxy tunnelling and framing as
//! [`Client`], over any asynchronous transport.
//!
//! The standard library has no async sockets or DNS, so the transport is supplied through the
//! [`Connect`] trait. [`ThreadConnector`] (the default) opens connections on the worker pool and
//! needs no setup; to use a runtime's own sockets, implement `Connect` with an adapter that
//! implements this crate's [`AsyncRead`] and [`AsyncWrite`] over them.
//!
//! ```no_run
//! use tiny_https::{asyncio::block_on, Client};
//! let client = Client::new()?.proxy_from_env().into_async();
//! let resp = block_on(client.get("https://example.com/"))?;
//! println!("{} {}", resp.status, resp.text());
//! # Ok::<(), tiny_https::error::Error>(())
//! ```
//!
//! Timeouts: this crate has no timer, so the client cannot time out a connector it does not
//! control. [`ThreadConnector`] enforces `connect_timeout`, `timeout` and `total_timeout` on its
//! sockets (they are blocking calls on worker threads); for another connector, the
//! [`ConnectOptions`] are handed to it and a timeout around the whole future is the executor's job.

use super::idle::{IdlePool, Key, Policy};
use super::parser::{keep_alive_timeout, Head, ResponseParser};
use super::stream::{is_peer_close, Failure};
use super::wire::{self, Limits};
use super::{
    check_connect_response, is_replayable, pool_key, tcp_connect, Client, ConnectOptions, Hop, Proxy, Response, Url, CONNECT_HEAD_LIMIT,
    REDIRECT_BODY_LIMIT, SMALL_BODY,
};
use crate::asyncio::{AsyncRead, AsyncReadExt, AsyncTlsStream, AsyncWrite, AsyncWriteExt, Pool, ThreadedStream};
use crate::error::{Error, Result};
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Instant;

/// Size of the buffer that chunk framing and the headers pass through.
const SCRATCH: usize = 32 * 1024;

/// Opens transport connections for an [`AsyncClient`].
pub trait Connect: Send + Sync {
    /// The connection type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Resolves `host` and connects to `port`. Plain TCP only: the client adds TLS itself.
    /// `opts` carries the client's timeouts; honour what the transport can.
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        opts: ConnectOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>>;

    /// Prepares a connection that has been waiting in the client's pool for a new request: apply
    /// the timeouts and deadline in `opts` to it (the ones it was opened with belong to an earlier
    /// request) and say whether it is still good, which means the peer has not closed it or sent
    /// anything while it waited. The default says no, so a connector gets no connection reuse
    /// until it implements this: a stream that does not know how to apply new limits, or to tell
    /// whether the peer hung up, would otherwise fail requests in ways that are hard to see.
    fn reuse(&self, stream: &mut Self::Stream, opts: ConnectOptions) -> bool {
        let _ = (stream, opts);
        false
    }
}

/// The default [`Connect`]: name resolution and connection run on a worker [`Pool`], and the
/// socket is a [`ThreadedStream`]. Works with any executor and enforces all of the client's
/// timeouts.
#[derive(Clone, Debug)]
pub struct ThreadConnector {
    pool: Pool,
}

impl ThreadConnector {
    pub fn new(pool: Pool) -> ThreadConnector {
        ThreadConnector { pool }
    }
}

impl Connect for ThreadConnector {
    type Stream = ThreadedStream;

    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        opts: ConnectOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<ThreadedStream>> + Send + 'a>> {
        let host = host.to_string();
        let pool = self.pool.clone();
        let task = self.pool.spawn_blocking(move || tcp_connect(&host, port, opts));
        Box::pin(async move {
            let io = task.await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.map_err(|e| match e {
                Error::Io(e) => e,
                other => io::Error::new(io::ErrorKind::Other, other.to_string()),
            })?;
            Ok(ThreadedStream::from_io(io, pool))
        })
    }

    fn reuse(&self, stream: &mut ThreadedStream, opts: ConnectOptions) -> bool {
        stream.rearm(opts.timeout, opts.deadline) && stream.peer_quiet()
    }
}

/// An HTTP(S) client for async code. Cheap to clone when the connector is.
///
/// Built from a configured [`Client`] (`client.into_async()` or [`AsyncClient::with_connector`]):
/// TLS settings, user agent, redirect limit, size limits, proxy, timeouts and the keep-alive
/// settings all come from it. The connections it keeps for reuse are its own (shared by its
/// clones), not the blocking client's.
pub struct AsyncClient<C: Connect = ThreadConnector> {
    client: Client,
    connector: C,
    idle: Arc<IdlePool<AsyncConn<C::Stream>>>,
}

impl<C: Connect + Clone> Clone for AsyncClient<C> {
    fn clone(&self) -> AsyncClient<C> {
        AsyncClient { client: self.client.clone(), connector: self.connector.clone(), idle: self.idle.clone() }
    }
}

impl Client {
    /// An async client with this client's settings, connecting through [`ThreadConnector`] on
    /// this client's pool (see [`Client::pool`]).
    pub fn into_async(self) -> AsyncClient {
        let connector = ThreadConnector::new(self.pool.clone().unwrap_or_else(Pool::global));
        AsyncClient { client: self, connector, idle: Arc::new(IdlePool::new()) }
    }
}

impl<C: Connect> AsyncClient<C> {
    /// An async client with `client`'s settings that opens connections with `connector`.
    pub fn with_connector(client: Client, connector: C) -> AsyncClient<C> {
        AsyncClient { client, connector, idle: Arc::new(IdlePool::new()) }
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        self.request("GET", url).send().await
    }

    pub async fn head(&self, url: &str) -> Result<Response> {
        self.request("HEAD", url).send().await
    }

    pub async fn post(&self, url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
        self.request("POST", url).body(body).send().await
    }

    /// [`get`](AsyncClient::get) with the body left to read as it arrives; see [`AsyncResponseStream`].
    pub async fn get_stream(&self, url: &str) -> Result<AsyncResponseStream<C::Stream>> {
        self.request("GET", url).send_stream().await
    }

    pub fn request(&self, method: &str, url: &str) -> AsyncRequestBuilder<'_, C> {
        AsyncRequestBuilder { client: self, method: method.to_string(), url: url.to_string(), headers: Vec::new(), body: Vec::new(), max_body: None }
    }

    /// Closes every idle connection this client (and its clones) is holding.
    pub fn close_idle_connections(&self) {
        self.idle.clear();
    }

    /// The number of idle connections waiting for another request.
    pub fn idle_connections(&self) -> usize {
        self.idle.len()
    }

    async fn execute(&self, method: String, url: &str, headers: Vec<(String, String)>, body: Vec<u8>, max_body: Option<u64>) -> Result<Response> {
        self.execute_stream(method, url, headers, body, max_body).await?.into_response().await
    }

    async fn execute_stream(
        &self,
        method: String,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        max_body: Option<u64>,
    ) -> Result<AsyncResponseStream<C::Stream>> {
        let mut hop = self.client.start(method, url, headers, body)?;
        let deadline = self.client.deadline();
        let limits = Limits { max_body_bytes: max_body.unwrap_or(self.client.limits.max_body_bytes), ..self.client.limits };
        let mut hops = 0;
        loop {
            let mut resp = self.once(&hop, deadline, limits).await?;
            if !self.client.follow(&mut hop, resp.status, &resp.headers, &mut hops)? {
                return Ok(resp);
            }
            // what is left of the redirect's body, if it is small, so that its connection can be used again
            if resp.content_length.map_or(true, |n| n <= REDIRECT_BODY_LIMIT) {
                resp.discard(REDIRECT_BODY_LIMIT).await;
            }
        }
    }

    /// One request on one connection (a pooled one if there is a good one, else a new one), up to the
    /// arrival of the response headers.
    async fn once(&self, hop: &Hop, deadline: Option<Instant>, limits: Limits) -> Result<AsyncResponseStream<C::Stream>> {
        let headers = self.client.request_headers(hop)?;
        let (method, url, body) = (hop.method.as_str(), &hop.url, hop.body.as_slice());
        let proxy = self.client.proxy_for(url)?;
        let key = pool_key(url, proxy.as_ref());
        let head = wire::write_request_head(method, &url.path_and_query, &headers);
        let policy = self.client.policy;
        let mut retry_allowed = policy.parks() && is_replayable(method, &hop.headers);
        let mut pooled_allowed = true;
        loop {
            let reused = if pooled_allowed { self.checkout(&key, deadline) } else { None };
            let was_reused = reused.is_some();
            let conn = match reused {
                Some(c) => c,
                None => self.connect(url, proxy.as_ref(), deadline).await?,
            };
            let home = policy.parks().then(|| AsyncHome { pool: self.idle.clone(), key: key.clone(), policy });
            match exchange(conn, method, url, &head, body, limits, home).await {
                Ok(stream) => return Ok(stream),
                // the server closed a connection that had been waiting: the request never reached
                // anything that could have acted on it, so it is sent once more on a new connection
                Err(f) if f.peer_closed && was_reused && retry_allowed => {
                    retry_allowed = false;
                    pooled_allowed = false;
                }
                Err(f) => return Err(f.error),
            }
        }
    }

    /// An idle connection to `key` that the connector says is still good, with the limits of the
    /// request that will use it.
    fn checkout(&self, key: &Key, deadline: Option<Instant>) -> Option<AsyncConn<C::Stream>> {
        if !self.client.policy.parks() {
            return None;
        }
        let opts = self.client.connect_options(deadline);
        while let Some(mut conn) = self.idle.take(key, Instant::now()) {
            if self.connector.reuse(conn.transport_mut(), opts) {
                return Some(conn);
            }
        }
        None
    }

    async fn connect(&self, url: &Url, proxy: Option<&Proxy>, deadline: Option<Instant>) -> Result<AsyncConn<C::Stream>> {
        let opts = self.client.connect_options(deadline);
        if !url.is_https() {
            return Ok(AsyncConn::Plain(self.connector.connect(&url.host, url.port, opts).await?));
        }
        let stream = match proxy {
            Some(proxy) => {
                let mut s = self.connector.connect(&proxy.host, proxy.port, opts).await?;
                s.write_all(self.client.connect_request(proxy, &url.host, url.port).as_bytes()).await?;
                s.flush().await?;
                // one byte at a time, so no tunnel data is consumed
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if head.len() > CONNECT_HEAD_LIMIT {
                        return Err(Error::Http("proxy response headers too large".into()));
                    }
                    if s.read(&mut byte).await? == 0 {
                        return Err(Error::Http("proxy closed the connection during CONNECT".into()));
                    }
                    head.push(byte[0]);
                }
                check_connect_response(&head)?;
                s
            }
            None => self.connector.connect(&url.host, url.port, opts).await?,
        };
        Ok(AsyncConn::Tls(Box::new(AsyncTlsStream::connect(stream, &url.host, &self.client.tls).await?)))
    }
}

/// Sends the request on `conn` and reads the response headers.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: AsyncConn<S>,
    method: &str,
    url: &Url,
    head: &[u8],
    body: &[u8],
    limits: Limits,
    home: Option<AsyncHome<S>>,
) -> std::result::Result<AsyncResponseStream<S>, Failure> {
    let mut reader = AsyncBody::new(conn, method, limits, home);
    reader.send_request(head, body).await?;
    let response_head = reader.receive_head().await?;
    Ok(AsyncResponseStream::new(response_head, url.clone(), reader))
}

/// A request being built; see [`AsyncClient::request`].
pub struct AsyncRequestBuilder<'a, C: Connect> {
    client: &'a AsyncClient<C>,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    max_body: Option<u64>,
}

impl<'a, C: Connect> AsyncRequestBuilder<'a, C> {
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Largest response body accepted for this request, in bytes; see [`Client::max_body_bytes`].
    pub fn max_body_bytes(mut self, n: u64) -> Self {
        self.max_body = Some(n);
        self
    }

    pub async fn send(self) -> Result<Response> {
        self.client.execute(self.method, &self.url, self.headers, self.body, self.max_body).await
    }

    /// Sends the request and returns as soon as the response headers are in; the body is read from
    /// the [`AsyncResponseStream`] as it arrives. Redirects are followed first; the stream is the
    /// final response.
    pub async fn send_stream(self) -> Result<AsyncResponseStream<C::Stream>> {
        self.client.execute_stream(self.method, &self.url, self.headers, self.body, self.max_body).await
    }
}

/// Plain or TLS, so the request code does not care which.
pub(super) enum AsyncConn<S> {
    Plain(S),
    Tls(Box<AsyncTlsStream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncConn<S> {
    /// The transport under the TLS, if there is any.
    fn transport_mut(&mut self) -> &mut S {
        match self {
            AsyncConn::Plain(s) => s,
            AsyncConn::Tls(s) => s.get_mut(),
        }
    }

    /// Digests what arrived with the end of the last response and says whether the connection is
    /// fit to wait for another request.
    fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        match self {
            AsyncConn::Plain(_) => Poll::Ready(true),
            AsyncConn::Tls(s) => s.poll_settle(cx),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncConn<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncConn<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_flush(cx),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_close(cx),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_close(cx),
        }
    }
}

/// Where a finished connection goes if it can be used again.
pub(super) struct AsyncHome<S> {
    pool: Arc<IdlePool<AsyncConn<S>>>,
    key: Key,
    policy: Policy,
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// The connection, the parser and the not-yet-delivered body bytes of one response: the
/// counterpart of the blocking client's `BodyReader`, driven by polling.
struct AsyncBody<S> {
    conn: Option<AsyncConn<S>>,
    parser: ResponseParser,
    home: Option<AsyncHome<S>>,
    /// Body bytes the parser produced that have not been handed out: `pending[pos..]`.
    pending: Vec<u8>,
    pos: usize,
    scratch: Vec<u8>,
    failed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncBody<S> {
    fn new(conn: AsyncConn<S>, method: &str, limits: Limits, home: Option<AsyncHome<S>>) -> AsyncBody<S> {
        AsyncBody { conn: Some(conn), parser: ResponseParser::new(method, limits), home, pending: Vec::new(), pos: 0, scratch: Vec::new(), failed: false }
    }

    async fn send_request(&mut self, head: &[u8], body: &[u8]) -> std::result::Result<(), Failure> {
        let conn = self.conn.as_mut().expect("a connection");
        let sent = async {
            if body.len() <= SMALL_BODY {
                let mut one = Vec::with_capacity(head.len() + body.len());
                one.extend_from_slice(head);
                one.extend_from_slice(body);
                conn.write_all(&one).await?;
            } else {
                // a large upload goes from the caller's slice, not through a second copy of it
                conn.write_all(head).await?;
                conn.write_all(body).await?;
            }
            conn.flush().await
        };
        sent.await.map_err(|e| {
            let error = Error::Io(e);
            Failure { peer_closed: is_peer_close(&error), error }
        })
    }

    /// Reads until the headers of the final response are complete and returns them.
    async fn receive_head(&mut self) -> std::result::Result<Head, Failure> {
        poll_fn(|cx| self.poll_head(cx)).await
    }

    fn poll_head(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<Head, Failure>> {
        if self.scratch.is_empty() {
            self.scratch = vec![0u8; SCRATCH];
        }
        while !self.parser.head_complete() {
            let want = self.parser.max_read().min(self.scratch.len());
            let conn = self.conn.as_mut().expect("a connection");
            let outcome = match Pin::new(conn).poll_read(cx, &mut self.scratch[..want]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => match self.parser.finish_eof(&mut self.pending) {
                    Err(e) => Err(e),
                    Ok(()) => Err(Error::Http("the response ended before its headers were complete".into())),
                },
                Poll::Ready(Ok(n)) => self.parser.feed(&self.scratch[..n], &mut self.pending),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                Poll::Ready(Err(e)) => Err(Error::Io(e)),
            };
            if let Err(error) = outcome {
                let peer_closed = !self.parser.started() && is_peer_close(&error);
                self.conn = None;
                self.failed = true;
                return Poll::Ready(Err(Failure { error, peer_closed }));
            }
        }
        let head = self.parser.take_head().expect("the head was complete");
        if let Some(home) = &mut self.home {
            // the server says how long it will wait: never wait longer than that for it
            if let Some(t) = keep_alive_timeout(&head.headers) {
                home.policy.idle_timeout = home.policy.idle_timeout.min(t);
            }
        }
        if self.parser.is_done() {
            // a connection that is not reused is closed politely, if that does not have to wait
            let _ = self.poll_complete(cx);
        }
        Poll::Ready(Ok(head))
    }

    /// The message has been read to its end: the connection goes back to the pool if it can be used
    /// again and is closed otherwise. Pending only while the TLS layer has something to send first.
    fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(conn) = self.conn.as_mut() else { return Poll::Ready(()) };
        let keep = match &self.home {
            Some(home) => self.parser.reusable() && home.policy.parks(),
            None => false,
        };
        if keep {
            match conn.poll_settle(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if let (Some(conn), Some(home)) = (self.conn.take(), self.home.take()) {
                        home.pool.put(home.key, conn, home.policy.idle_timeout, &home.policy, Instant::now());
                    }
                    return Poll::Ready(());
                }
                Poll::Ready(false) => {}
            }
        }
        // goodbye (TLS close_notify) if the transport takes it at once; errors do not matter now
        let _ = Pin::new(&mut *conn).poll_close(cx);
        self.conn = None;
        self.home = None;
        Poll::Ready(())
    }

    fn broken(&mut self, e: Error) -> Error {
        self.conn = None;
        self.home = None;
        self.failed = true;
        e
    }

    /// Reads body bytes into `out`; 0 is the end of the body. The size limit, the framing and the
    /// timeouts are enforced here.
    fn poll_read_body(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.failed {
            return Poll::Ready(Err(Error::Http("the response failed earlier and cannot be read further".into())));
        }
        loop {
            if self.pos < self.pending.len() {
                let n = (self.pending.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(n));
            }
            self.pending.clear();
            self.pos = 0;
            if self.parser.is_done() {
                ready!(self.poll_complete(cx));
                return Poll::Ready(Ok(0));
            }
            let window = self.parser.direct_window();
            let Some(conn) = self.conn.as_mut() else { return Poll::Ready(Ok(0)) };
            if window > 0 {
                // body bytes that need no parsing go straight to the caller
                let want = window.min(out.len());
                match Pin::new(conn).poll_read(cx, &mut out[..want]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(e) = self.parser.consume_direct(n) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                        if self.parser.is_done() {
                            let _ = self.poll_complete(cx);
                        }
                        return Poll::Ready(Ok(n));
                    }
                    Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(self.broken(Error::Io(e)))),
                }
            } else {
                if self.scratch.is_empty() {
                    self.scratch = vec![0u8; SCRATCH];
                }
                let want = self.parser.max_read().min(self.scratch.len());
                match Pin::new(conn).poll_read(cx, &mut self.scratch[..want]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(e) = self.parser.feed(&self.scratch[..n], &mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                        if self.parser.is_done() {
                            let _ = self.poll_complete(cx);
                        }
                    }
                    Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(self.broken(Error::Io(e)))),
                }
            }
        }
    }

    async fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        poll_fn(|cx| self.poll_read_body(cx, out)).await
    }

    /// Reads and drops up to `limit` bytes of what is left of the body, so that a connection whose
    /// response nobody wants (a redirect's) can be used again. Gives up, and closes the connection,
    /// beyond that.
    async fn discard(&mut self, limit: u64) {
        let mut sink = [0u8; 8192];
        let mut seen = 0u64;
        while seen < limit {
            match self.read_body(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(n) => seen += n as u64,
            }
        }
        // too much to be worth it
        self.conn = None;
        self.home = None;
    }
}

/// A response whose head has arrived and whose body is read as it comes, for async code: the
/// counterpart of [`ResponseStream`](super::ResponseStream).
///
/// `status`, `headers` and `content_length` are known when this is returned; the body is read with
/// [`AsyncRead`] ([`into_response`](AsyncResponseStream::into_response) buffers what is left). The
/// body is limited by the client's [`max_body_bytes`](Client::max_body_bytes) (or the request's own)
/// and by the client's timeouts. A body over the limit is an error, reported by the request itself
/// if the head declares a length over the limit or the first read already holds more than the limit,
/// and by a later read otherwise. A connection whose body was read to its end may be reused;
/// dropping the stream earlier closes it.
pub struct AsyncResponseStream<S = ThreadedStream> {
    pub status: u16,
    pub reason: String,
    /// The protocol the response came over (always HTTP/1.1 for now: this client does not speak HTTP/2).
    pub version: super::HttpVersion,
    pub headers: Vec<(String, String)>,
    /// The URL that produced this response (after redirects).
    pub url: Url,
    /// The Content-Length the server declared, if it declared one and the body is not chunked.
    /// Known before the body is read. For a response to HEAD, the length a GET would have.
    pub content_length: Option<u64>,
    body: AsyncBody<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncResponseStream<S> {
    fn new(head: Head, url: Url, body: AsyncBody<S>) -> AsyncResponseStream<S> {
        AsyncResponseStream { status: head.status, reason: head.reason, version: super::HttpVersion::Http11, headers: head.headers, url, content_length: head.content_length, body }
    }

    /// First header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// All headers with this (case-insensitive) name.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Reads the rest of the body into memory and returns the whole [`Response`].
    pub async fn into_response(mut self) -> Result<Response> {
        let mut body: Vec<u8> = Vec::new();
        if !self.body.parser.is_done() {
            // what the server says is coming is a hint, not a promise: never reserve more than a megabyte up front
            body.reserve(self.content_length.unwrap_or(0).min(1 << 20) as usize);
        }
        loop {
            if body.capacity() - body.len() < 4096 {
                body.reserve(body.len().max(32 * 1024));
            }
            let len = body.len();
            let room = (body.capacity() - len).min(1 << 20);
            body.resize(len + room, 0);
            match self.body.read_body(&mut body[len..]).await {
                Ok(0) => {
                    body.truncate(len);
                    break;
                }
                Ok(n) => body.truncate(len + n),
                Err(e) => return Err(e),
            }
        }
        Ok(Response { status: self.status, reason: self.reason, version: self.version, headers: self.headers, body, url: self.url })
    }

    /// Reads the rest of the body into `sink`; returns how many bytes it was.
    pub async fn copy_to<W: AsyncWrite + Unpin>(&mut self, sink: &mut W) -> Result<u64> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            match self.body.read_body(&mut buf).await? {
                0 => return Ok(total),
                n => {
                    sink.write_all(&buf[..n]).await?;
                    total += n as u64;
                }
            }
        }
    }

    async fn discard(&mut self, limit: u64) {
        self.body.discard(limit).await;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for AsyncResponseStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.body.poll_read_body(cx, buf).map_err(to_io)
    }
}

impl<S> std::fmt::Debug for AsyncResponseStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncResponseStream").field("status", &self.status).field("url", &self.url.to_string()).field("content_length", &self.content_length).finish_non_exhaustive()
    }
}
