use anyhow::{Result, anyhow};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    Request(RequestHead),
    Response(ResponseHead),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
}

pub fn parse_head(bytes: &[u8]) -> Result<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(bytes)? {
        httparse::Status::Complete(_) if req.method.is_some() => Ok(Head::Request(RequestHead {
            method: req.method.unwrap().to_owned(),
            target: req.path.unwrap_or_default().to_owned(),
            version: format!("HTTP/1.{}", req.version.unwrap_or(1)),
            headers: collect(req.headers),
        })),
        _ => {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(bytes)? {
                httparse::Status::Complete(_) => Ok(Head::Response(ResponseHead {
                    status: resp.code.ok_or_else(|| anyhow!("response has no status"))?,
                    reason: resp.reason.unwrap_or_default().to_owned(),
                    version: format!("HTTP/1.{}", resp.version.unwrap_or(1)),
                    headers: collect(resp.headers),
                })),
                _ => Err(anyhow!("incomplete or invalid HTTP/1 header")),
            }
        }
    }
}
fn collect(headers: &[httparse::Header<'_>]) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).trim().to_owned(),
            )
        })
        .collect()
}

pub fn header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}
pub fn content_length(headers: &BTreeMap<String, String>) -> Option<usize> {
    headers.get("content-length")?.parse().ok()
}
pub fn is_chunked(headers: &BTreeMap<String, String>) -> bool {
    headers.get("transfer-encoding").is_some_and(|v| {
        v.to_ascii_lowercase()
            .split(',')
            .any(|x| x.trim() == "chunked")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_headers_case_insensitively() {
        let parsed =
            parse_head(b"GET /ok HTTP/1.1\r\nHost: example.test\r\nX-A: b\r\n\r\n").unwrap();
        let Head::Request(request) = parsed else {
            panic!("expected request")
        };
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers["host"], "example.test");
    }
}
