use crate::{
    certs::{self, CaPaths},
    events::{Direction, Endpoint, EventKind, TrafficEvent},
    hooks::{HookPhase, InterceptionAction, SharedHookEngine},
    parsers::{
        certificate,
        http1::{self, Head, RequestHead, ResponseHead},
    },
    store::EventStore,
};
use anyhow::{Context, Result, anyhow};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone)]
pub struct ProxyOptions {
    pub listen: SocketAddr,
    pub mitm: bool,
    pub ca: Option<CaPaths>,
    pub hooks: SharedHookEngine,
    pub store: EventStore,
    pub max_hook_json_body_bytes: usize,
}

pub async fn run(options: ProxyOptions) -> Result<()> {
    if options.mitm && options.ca.is_none() {
        return Err(anyhow!(
            "--mitm requires --ca-dir containing netscope-ca.pem and netscope-ca-key.pem"
        ));
    }
    let listener = TcpListener::bind(options.listen).await?;
    tracing::info!(address=%options.listen,"proxy listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let options = options.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, peer, options.clone()).await {
                tracing::debug!(%peer,error=%e,"proxy connection ended");
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    options: ProxyOptions,
) -> Result<()> {
    let head = read_head(&mut client).await?;
    let request = match head {
        Head::Request(r) => r,
        _ => return Err(anyhow!("client sent HTTP response")),
    };
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = authority(&request.target, 443)?;
        let destination = Endpoint::new(&host, port);
        let source = Endpoint::new(peer.ip().to_string(), peer.port());
        let id = connection_id(&source, &destination);
        options
            .store
            .emit(TrafficEvent::new(
                id.clone(),
                Direction::ClientToServer,
                source.clone(),
                destination.clone(),
                EventKind::Tunnel {
                    authority: request.target.clone(),
                    intercepted: options.mitm,
                },
            ))
            .await;
        let upstream = TcpStream::connect((host.as_str(), port))
            .await
            .context("connect CONNECT target")?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: netscope\r\n\r\n")
            .await?;
        if !options.mitm {
            let mut upstream = upstream;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            return Ok(());
        }
        let config = certs::load_server_config(options.ca.as_ref().unwrap(), &host)?;
        let downstream = TlsAcceptor::from(Arc::new(config))
            .accept(client)
            .await
            .context("TLS handshake with client")?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| anyhow!("invalid target hostname"))?;
        let tls_upstream = TlsConnector::from(Arc::new(client_config()))
            .connect(server_name, upstream)
            .await
            .context("TLS handshake with target")?;
        emit_peer_certificate(&options.store, &id, &source, &destination, &tls_upstream).await;
        process_connection(
            downstream,
            tls_upstream,
            source,
            destination,
            id,
            options,
            true,
        )
        .await
    } else {
        let (host, port) = request_destination(&request)?;
        let destination = Endpoint::new(&host, port);
        let source = Endpoint::new(peer.ip().to_string(), peer.port());
        let id = connection_id(&source, &destination);
        // Decide the first plain-HTTP request before opening an upstream socket. This is what
        // makes `respond` a genuine local synthetic response rather than a replacement after a
        // network connection has already been made.
        let event = request_event(&id, &source, &destination, &request);
        let initial_action = options
            .hooks
            .decide(HookPhase::RequestHeaders, event.clone(), None)
            .await;
        options.store.emit(event).await;
        let initial_action = match initial_action {
            InterceptionAction::Drop { .. } => {
                drain_body(&mut client, &request.headers).await?;
                return Ok(());
            }
            InterceptionAction::Respond {
                status,
                headers,
                body,
            } => {
                drain_body(&mut client, &request.headers).await?;
                write_replacement(&mut client, status.unwrap_or(200), headers, body).await?;
                return Ok(());
            }
            InterceptionAction::Delay { milliseconds } => {
                tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
                InterceptionAction::Continue
            }
            action => action,
        };
        let upstream = TcpStream::connect((host.as_str(), port))
            .await
            .context("connect HTTP target")?;
        process_connection_with_first(
            client,
            upstream,
            request,
            source,
            destination,
            id,
            options,
            false,
            Some(initial_action),
        )
        .await
    }
}

async fn emit_peer_certificate(
    store: &EventStore,
    id: &str,
    source: &Endpoint,
    destination: &Endpoint,
    stream: &tokio_rustls::client::TlsStream<TcpStream>,
) {
    let Some(certificate) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
    else {
        return;
    };
    let Ok(summary) = certificate::parse_certificate(certificate.as_ref()) else {
        return;
    };
    store
        .emit(TrafficEvent::new(
            id,
            Direction::ServerToClient,
            destination.clone(),
            source.clone(),
            EventKind::TlsCertificate {
                subject: Some(summary.subject),
                issuer: Some(summary.issuer),
                serial: Some(summary.serial),
                not_after: Some(summary.not_after),
            },
        ))
        .await;
}

fn client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}
fn connection_id(source: &Endpoint, dest: &Endpoint) -> String {
    format!(
        "{}:{}-{}:{}",
        source.host, source.port, dest.host, dest.port
    )
}

async fn process_connection<C, U>(
    client: C,
    upstream: U,
    source: Endpoint,
    destination: Endpoint,
    id: String,
    options: ProxyOptions,
    tls: bool,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    process_loop(
        client,
        upstream,
        None,
        source,
        destination,
        id,
        options,
        tls,
        None,
    )
    .await
}
#[allow(clippy::too_many_arguments)] // This adapts a parsed first request into the common loop.
async fn process_connection_with_first<C, U>(
    client: C,
    upstream: U,
    first: RequestHead,
    source: Endpoint,
    destination: Endpoint,
    id: String,
    options: ProxyOptions,
    tls: bool,
    initial_action: Option<InterceptionAction>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    process_loop(
        client,
        upstream,
        Some(first),
        source,
        destination,
        id,
        options,
        tls,
        initial_action,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Endpoint identity and options remain explicit at this I/O boundary.
async fn process_loop<C, U>(
    mut client: C,
    mut upstream: U,
    mut first: Option<RequestHead>,
    source: Endpoint,
    destination: Endpoint,
    id: String,
    options: ProxyOptions,
    _tls: bool,
    mut initial_action: Option<InterceptionAction>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    options
        .store
        .emit(TrafficEvent::new(
            id.clone(),
            Direction::ClientToServer,
            source.clone(),
            destination.clone(),
            EventKind::ConnectionOpened {
                transport: "tcp".into(),
            },
        ))
        .await;
    'connection: loop {
        let req = match first.take() {
            Some(r) => r,
            None => match read_head(&mut client).await {
                Ok(Head::Request(r)) => r,
                Ok(_) => return Err(anyhow!("expected request")),
                Err(e) if is_eof(&e) => break,
                Err(e) => return Err(e),
            },
        };
        let event = request_event(&id, &source, &destination, &req);
        let action = match initial_action.take() {
            Some(action) => action,
            None => {
                let action = options
                    .hooks
                    .decide(HookPhase::RequestHeaders, event.clone(), None)
                    .await;
                options.store.emit(event).await;
                action
            }
        };
        let request_closes = req
            .headers
            .get("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let req = match action {
            InterceptionAction::Drop { .. } => {
                drain_body(&mut client, &req.headers).await?;
                break 'connection;
            }
            InterceptionAction::Respond {
                status,
                headers,
                body,
            } => {
                drain_body(&mut client, &req.headers).await?;
                write_replacement(&mut client, status.unwrap_or(200), headers, body).await?;
                continue;
            }
            InterceptionAction::Modify {
                set_headers,
                remove_headers,
                body: _,
            } => modify_request(req, set_headers, remove_headers),
            InterceptionAction::Delay { milliseconds } => {
                tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
                req
            }
            InterceptionAction::Continue => req,
        };
        if options.hooks.wants_json_bodies().await
            && let Some(length) = json_body_length(&req.headers, options.max_hook_json_body_bytes)
        {
            let body = read_fixed_body(&mut client, length).await?;
            let event = body_event(
                &id,
                Direction::ClientToServer,
                &source,
                &destination,
                &req.headers,
                body.len(),
            );
            let action = options
                .hooks
                .decide(HookPhase::RequestBody, event.clone(), Some(&body))
                .await;
            options.store.emit(event).await;
            let (req, body) = match action {
                InterceptionAction::Continue => (req, body),
                InterceptionAction::Delay { milliseconds } => {
                    tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
                    (req, body)
                }
                InterceptionAction::Modify {
                    set_headers,
                    remove_headers,
                    body: replacement,
                } => {
                    let mut req = modify_request(req, set_headers, remove_headers);
                    let body = replacement.unwrap_or(body);
                    set_fixed_body_headers(&mut req.headers, body.len());
                    (req, body)
                }
                InterceptionAction::Drop { .. } => break 'connection,
                InterceptionAction::Respond {
                    status,
                    headers,
                    body,
                } => {
                    write_replacement(&mut client, status.unwrap_or(200), headers, body).await?;
                    continue;
                }
            };
            write_request_head(&mut upstream, &req).await?;
            upstream.write_all(&body).await?;
            upstream.flush().await?;
        } else {
            forward_request(&mut client, &mut upstream, &req).await?;
        }
        let response = match read_head(&mut upstream).await? {
            Head::Response(r) => r,
            _ => return Err(anyhow!("upstream sent a request")),
        };
        let response_event = response_event(&id, &source, &destination, &response);
        let action = options
            .hooks
            .decide(HookPhase::ResponseHeaders, response_event.clone(), None)
            .await;
        options.store.emit(response_event).await;
        let response = match action {
            InterceptionAction::Drop { .. } => {
                drain_response_body(&mut upstream, &response).await?;
                break 'connection;
            }
            InterceptionAction::Respond {
                status,
                headers,
                body,
            } => {
                drain_response_body(&mut upstream, &response).await?;
                write_replacement(&mut client, status.unwrap_or(200), headers, body).await?;
                continue;
            }
            InterceptionAction::Modify {
                set_headers,
                remove_headers,
                body: _,
            } => modify_response(response, set_headers, remove_headers),
            InterceptionAction::Delay { milliseconds } => {
                tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
                response
            }
            InterceptionAction::Continue => response,
        };
        let response_status = response.status;
        let response_closes = response
            .headers
            .get("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let mut upstream_finished = false;
        if options.hooks.wants_json_bodies().await
            && let Some(length) =
                json_body_length(&response.headers, options.max_hook_json_body_bytes)
        {
            let body = read_fixed_body(&mut upstream, length).await?;
            let event = body_event(
                &id,
                Direction::ServerToClient,
                &destination,
                &source,
                &response.headers,
                body.len(),
            );
            let action = options
                .hooks
                .decide(HookPhase::ResponseBody, event.clone(), Some(&body))
                .await;
            options.store.emit(event).await;
            let (response, body) = match action {
                InterceptionAction::Continue => (response, body),
                InterceptionAction::Delay { milliseconds } => {
                    tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
                    (response, body)
                }
                InterceptionAction::Modify {
                    set_headers,
                    remove_headers,
                    body: replacement,
                } => {
                    let mut response = modify_response(response, set_headers, remove_headers);
                    let body = replacement.unwrap_or(body);
                    set_fixed_body_headers(&mut response.headers, body.len());
                    (response, body)
                }
                InterceptionAction::Drop { .. } => break 'connection,
                InterceptionAction::Respond {
                    status,
                    headers,
                    body,
                } => {
                    write_replacement(&mut client, status.unwrap_or(200), headers, body).await?;
                    continue;
                }
            };
            write_response_head(&mut client, &response).await?;
            client.write_all(&body).await?;
            client.flush().await?;
        } else {
            write_response_head(&mut client, &response).await?;
            if relay_response_body(&mut upstream, &mut client, &response).await? {
                upstream_finished = true;
            }
        }
        if response_status == 101 {
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            break 'connection;
        }
        if request_closes || response_closes || upstream_finished {
            break 'connection;
        }
    }
    options
        .store
        .emit(TrafficEvent::new(
            id,
            Direction::Unknown,
            source,
            destination,
            EventKind::ConnectionClosed { reason: None },
        ))
        .await;
    Ok(())
}

async fn forward_request<C: AsyncRead + AsyncWrite + Unpin, U: AsyncRead + AsyncWrite + Unpin>(
    client: &mut C,
    upstream: &mut U,
    req: &RequestHead,
) -> Result<()> {
    write_request_head(upstream, req).await?;
    relay_body(client, upstream, &req.headers).await
}
fn json_body_length(headers: &BTreeMap<String, String>, maximum: usize) -> Option<usize> {
    let content_type = headers.get("content-type")?.to_ascii_lowercase();
    let is_json = content_type.starts_with("application/json") || content_type.contains("+json");
    let length = http1::content_length(headers)?;
    (is_json && !headers.contains_key("content-encoding") && length <= maximum).then_some(length)
}
async fn read_fixed_body<R: AsyncRead + Unpin>(reader: &mut R, length: usize) -> Result<Vec<u8>> {
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    Ok(body)
}
fn set_fixed_body_headers(headers: &mut BTreeMap<String, String>, length: usize) {
    headers.remove("transfer-encoding");
    headers.insert("content-length".into(), length.to_string());
}
fn body_event(
    id: &str,
    direction: Direction,
    source: &Endpoint,
    destination: &Endpoint,
    headers: &BTreeMap<String, String>,
    length: usize,
) -> TrafficEvent {
    TrafficEvent::new(
        id,
        direction.clone(),
        source.clone(),
        destination.clone(),
        EventKind::HttpBody {
            direction,
            length,
            content_type: headers.get("content-type").cloned(),
        },
    )
}
async fn read_head<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Head> {
    let mut b = Vec::with_capacity(1024);
    loop {
        let mut one = [0u8; 1];
        let n = reader.read(&mut one).await?;
        if n == 0 {
            return Err(anyhow!("EOF while reading HTTP header"));
        }
        b.push(one[0]);
        if b.len() > 64 * 1024 {
            return Err(anyhow!("HTTP header exceeds 64 KiB"));
        }
        if http1::header_end(&b).is_some() {
            return http1::parse_head(&b);
        }
    }
}
async fn relay_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut R,
    to: &mut W,
    headers: &BTreeMap<String, String>,
) -> Result<()> {
    if let Some(n) = http1::content_length(headers) {
        copy_exact(from, to, n).await
    } else if http1::is_chunked(headers) {
        relay_chunked(from, to).await
    } else {
        Ok(())
    }
}
async fn drain_body<R: AsyncRead + Unpin>(
    from: &mut R,
    headers: &BTreeMap<String, String>,
) -> Result<()> {
    let mut sink = tokio::io::sink();
    relay_body(from, &mut sink, headers).await
}
async fn relay_response_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut R,
    to: &mut W,
    response: &ResponseHead,
) -> Result<bool> {
    if (100..200).contains(&response.status) || matches!(response.status, 204 | 304) {
        return Ok(false);
    }
    if http1::content_length(&response.headers).is_some() || http1::is_chunked(&response.headers) {
        relay_body(from, to, &response.headers).await?;
        return Ok(false);
    }
    let mut buffer = [0_u8; 8192];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            to.flush().await?;
            return Ok(true);
        }
        to.write_all(&buffer[..read]).await?;
    }
}
async fn drain_response_body<R: AsyncRead + Unpin>(
    from: &mut R,
    response: &ResponseHead,
) -> Result<bool> {
    let mut sink = tokio::io::sink();
    relay_response_body(from, &mut sink, response).await
}
async fn copy_exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut R,
    to: &mut W,
    mut n: usize,
) -> Result<()> {
    let mut b = [0u8; 8192];
    while n > 0 {
        let take = n.min(b.len());
        from.read_exact(&mut b[..take]).await?;
        to.write_all(&b[..take]).await?;
        n -= take;
    }
    to.flush().await?;
    Ok(())
}
async fn relay_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut R,
    to: &mut W,
) -> Result<()> {
    loop {
        let line = read_line(from).await?;
        to.write_all(&line).await?;
        let text = std::str::from_utf8(&line)?.trim();
        let size = usize::from_str_radix(text.split(';').next().unwrap_or(""), 16)
            .context("invalid chunk size")?;
        if size == 0 {
            loop {
                let trailer = read_line(from).await?;
                to.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    to.flush().await?;
                    return Ok(());
                }
            }
        }
        copy_exact(from, to, size + 2).await?;
    }
}
async fn read_line<R: AsyncRead + Unpin>(from: &mut R) -> Result<Vec<u8>> {
    let mut line = vec![];
    loop {
        let mut one = [0];
        from.read_exact(&mut one).await?;
        line.push(one[0]);
        if line.len() > 8192 {
            return Err(anyhow!("line too long"));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}
async fn write_request_head<W: AsyncWrite + Unpin>(out: &mut W, req: &RequestHead) -> Result<()> {
    let target = origin_target(&req.target);
    out.write_all(format!("{} {} {}\r\n", req.method, target, req.version).as_bytes())
        .await?;
    write_headers(out, &req.headers).await
}
async fn write_response_head<W: AsyncWrite + Unpin>(out: &mut W, res: &ResponseHead) -> Result<()> {
    out.write_all(format!("{} {} {}\r\n", res.version, res.status, res.reason).as_bytes())
        .await?;
    write_headers(out, &res.headers).await
}
async fn write_headers<W: AsyncWrite + Unpin>(
    out: &mut W,
    headers: &BTreeMap<String, String>,
) -> Result<()> {
    for (k, v) in headers {
        out.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
    }
    out.write_all(b"\r\n").await?;
    out.flush().await?;
    Ok(())
}
async fn write_replacement<W: AsyncWrite + Unpin>(
    out: &mut W,
    status: u16,
    mut headers: BTreeMap<String, String>,
    body: Vec<u8>,
) -> Result<()> {
    headers.insert("content-length".into(), body.len().to_string());
    headers
        .entry("content-type".into())
        .or_insert_with(|| "text/plain; charset=utf-8".into());
    let r = ResponseHead {
        status,
        reason: "Intercepted".into(),
        version: "HTTP/1.1".into(),
        headers,
    };
    write_response_head(out, &r).await?;
    out.write_all(&body).await?;
    out.flush().await?;
    Ok(())
}
fn request_event(id: &str, s: &Endpoint, d: &Endpoint, r: &RequestHead) -> TrafficEvent {
    TrafficEvent::new(
        id,
        Direction::ClientToServer,
        s.clone(),
        d.clone(),
        EventKind::HttpRequest {
            method: r.method.clone(),
            target: r.target.clone(),
            version: r.version.clone(),
            headers: r.headers.clone(),
        },
    )
}
fn response_event(id: &str, s: &Endpoint, d: &Endpoint, r: &ResponseHead) -> TrafficEvent {
    TrafficEvent::new(
        id,
        Direction::ServerToClient,
        d.clone(),
        s.clone(),
        EventKind::HttpResponse {
            status: r.status,
            reason: r.reason.clone(),
            headers: r.headers.clone(),
        },
    )
}
fn modify_request(
    mut r: RequestHead,
    set: BTreeMap<String, String>,
    remove: Vec<String>,
) -> RequestHead {
    modify_headers(&mut r.headers, set, remove);
    r
}
fn modify_response(
    mut r: ResponseHead,
    set: BTreeMap<String, String>,
    remove: Vec<String>,
) -> ResponseHead {
    modify_headers(&mut r.headers, set, remove);
    r
}
fn modify_headers(
    headers: &mut BTreeMap<String, String>,
    set: BTreeMap<String, String>,
    remove: Vec<String>,
) {
    for k in remove {
        headers.remove(&k.to_ascii_lowercase());
    }
    for (k, v) in set {
        headers.insert(k.to_ascii_lowercase(), v);
    }
}
fn authority(value: &str, default: u16) -> Result<(String, u16)> {
    let v = value.trim();
    if let Some((h, p)) = v.rsplit_once(':')
        && !h.contains(']')
    {
        return Ok((h.trim_matches(['[', ']']).to_owned(), p.parse()?));
    }
    Ok((v.trim_matches(['[', ']']).to_owned(), default))
}
fn request_destination(r: &RequestHead) -> Result<(String, u16)> {
    if let Some(rest) = r.target.strip_prefix("http://") {
        let auth = rest.split('/').next().unwrap_or(rest);
        authority(auth, 80)
    } else if let Some(host) = r.headers.get("host") {
        authority(host, 80)
    } else {
        Err(anyhow!("HTTP request has no Host header"))
    }
}
fn origin_target(target: &str) -> &str {
    if let Some(after) = target.strip_prefix("http://") {
        after.find('/').map(|n| &after[n..]).unwrap_or("/")
    } else {
        target
    }
}
fn is_eof(e: &anyhow::Error) -> bool {
    e.to_string().contains("EOF")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn absolute_target_becomes_origin_form() {
        assert_eq!(origin_target("http://example.test/a?b"), "/a?b");
        assert_eq!(origin_target("http://example.test"), "/");
    }
    #[test]
    fn modifier_is_case_insensitive() {
        let mut h = BTreeMap::from([("x-old".into(), "yes".into())]);
        modify_headers(
            &mut h,
            BTreeMap::from([("X-New".into(), "ok".into())]),
            vec!["X-OLD".into()],
        );
        assert_eq!(h.get("x-new"), Some(&"ok".to_string()));
        assert!(!h.contains_key("x-old"));
    }

    #[test]
    fn only_bounded_uncompressed_json_is_buffered_for_hooks() {
        let json = BTreeMap::from([
            (
                "content-type".into(),
                "application/json; charset=utf-8".into(),
            ),
            ("content-length".into(), "12".into()),
        ]);
        assert_eq!(json_body_length(&json, 16), Some(12));
        assert_eq!(json_body_length(&json, 8), None);
        let compressed = BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("content-length".into(), "12".into()),
            ("content-encoding".into(), "gzip".into()),
        ]);
        assert_eq!(json_body_length(&compressed, 16), None);
    }

    #[tokio::test]
    async fn replacement_writes_a_self_contained_http_response() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_replacement(
            &mut writer,
            418,
            BTreeMap::from([("x-intercepted".into(), "yes".into())]),
            b"blocked".to_vec(),
        )
        .await
        .unwrap();
        writer.shutdown().await.unwrap();
        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 418 Intercepted\r\n"));
        assert!(text.contains("content-length: 7\r\n"));
        assert!(text.ends_with("\r\n\r\nblocked"));
    }
}
