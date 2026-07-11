use anyhow::{Result, anyhow};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub tls_version: String,
    pub cipher_suites: Vec<String>,
}
/// A bounds-checked, intentionally partial TLS ClientHello parser for passive metadata extraction.
pub fn parse_client_hello(record: &[u8]) -> Result<ClientHello> {
    if record.len() < 9 || record[0] != 22 || record[5] != 1 {
        return Err(anyhow!("not a TLS ClientHello record"));
    }
    let hs_len = u24(&record[6..9])?;
    if record.len() < 9 + hs_len {
        return Err(anyhow!("truncated ClientHello"));
    }
    let legacy_version = u16at(record, 9)?;
    let mut p = 9 + 2 + 32;
    if p >= record.len() {
        return Err(anyhow!("truncated hello"));
    }
    let sid = record[p] as usize;
    p += 1 + sid;
    let suites = u16at(record, p)? as usize;
    if !suites.is_multiple_of(2) || p + 2 + suites > record.len() {
        return Err(anyhow!("truncated cipher suites"));
    }
    let cipher_suites = record[p + 2..p + 2 + suites]
        .chunks_exact(2)
        .map(|suite| format!("0x{:02x}{:02x}", suite[0], suite[1]))
        .collect();
    p += 2 + suites;
    let comp = *record
        .get(p)
        .ok_or_else(|| anyhow!("truncated compression"))? as usize;
    p += 1 + comp;
    let ext_len = u16at(record, p)? as usize;
    p += 2;
    let end = p + ext_len;
    if end > record.len() {
        return Err(anyhow!("truncated extensions"));
    }
    let mut sni = None;
    let mut alpn = vec![];
    let mut supported_version = None;
    while p + 4 <= end {
        let ty = u16at(record, p)?;
        let n = u16at(record, p + 2)? as usize;
        p += 4;
        if p + n > end {
            return Err(anyhow!("bad extension length"));
        }
        let data = &record[p..p + n];
        p += n;
        if ty == 0 && data.len() >= 5 {
            let list = u16::from_be_bytes([data[0], data[1]]) as usize;
            if list + 2 <= data.len() && data[2] == 0 {
                let len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if len > 0 && 5 + len <= data.len() {
                    sni = Some(String::from_utf8_lossy(&data[5..5 + len]).to_string());
                }
            }
        }
        if ty == 16 && data.len() >= 2 {
            let mut q = 2;
            let list = u16::from_be_bytes([data[0], data[1]]) as usize;
            let limit = (2 + list).min(data.len());
            while q < limit {
                let n = data[q] as usize;
                q += 1;
                if q + n > limit {
                    break;
                }
                alpn.push(String::from_utf8_lossy(&data[q..q + n]).to_string());
                q += n;
            }
        }
        // supported_versions: ClientHello contains a one-byte byte-length followed by u16 values.
        if ty == 43 && !data.is_empty() {
            let list_len = data[0] as usize;
            if list_len >= 2 && list_len < data.len() {
                supported_version = Some(u16::from_be_bytes([data[1], data[2]]));
            }
        }
    }
    Ok(ClientHello {
        sni,
        alpn,
        tls_version: tls_version(supported_version.unwrap_or(legacy_version)),
        cipher_suites,
    })
}

/// Extracts the leaf DER certificate from an unencrypted TLS 1.0-1.2 Certificate
/// handshake. TLS 1.3 encrypts this handshake and intentionally returns no result.
pub fn parse_server_certificate(record_stream: &[u8]) -> Result<Vec<u8>> {
    let mut p = 0;
    while p + 5 <= record_stream.len() {
        let content_type = record_stream[p];
        let record_length = u16at(record_stream, p + 3)? as usize;
        let end = p + 5 + record_length;
        if end > record_stream.len() {
            return Err(anyhow!("truncated TLS record"));
        }
        let record = &record_stream[p + 5..end];
        if content_type == 22 && record.len() >= 7 && record[0] == 11 {
            let handshake_length = u24(&record[1..4])?;
            if 4 + handshake_length > record.len() {
                return Err(anyhow!("truncated TLS Certificate handshake"));
            }
            let body = &record[4..4 + handshake_length];
            let list_length = u24(body
                .get(..3)
                .ok_or_else(|| anyhow!("truncated certificate list"))?)?;
            if list_length < 3 || 3 + list_length > body.len() {
                return Err(anyhow!("truncated certificate list"));
            }
            let certificate_length = u24(&body[3..6])?;
            if certificate_length == 0 || 6 + certificate_length > body.len() {
                return Err(anyhow!("truncated leaf certificate"));
            }
            return Ok(body[6..6 + certificate_length].to_vec());
        }
        p = end;
    }
    Err(anyhow!("no TLS Certificate handshake"))
}
fn tls_version(version: u16) -> String {
    match version {
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        _ => format!("0x{version:04x}"),
    }
}
fn u16at(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([
        *b.get(p).ok_or_else(|| anyhow!("truncated"))?,
        *b.get(p + 1).ok_or_else(|| anyhow!("truncated"))?,
    ]))
}
fn u24(b: &[u8]) -> Result<usize> {
    if b.len() != 3 {
        return Err(anyhow!("bad u24"));
    }
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_and_alpn() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
        let name = b"example.com";
        let mut extensions = vec![0, 0, 0, 16, 0, 14, 0, 0, name.len() as u8];
        extensions.extend_from_slice(name);
        extensions.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut record = vec![22, 3, 1];
        let length = body.len() + 4;
        record.extend_from_slice(&(length as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        record.extend_from_slice(&body);
        let hello = parse_client_hello(&record).unwrap();
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec!["h2"]);
        assert_eq!(hello.tls_version, "TLS 1.2");
        assert_eq!(hello.cipher_suites, vec!["0x1301"]);
    }

    #[test]
    fn extracts_an_unencrypted_tls_12_leaf_certificate() {
        let body = [0, 0, 6, 0, 0, 3, 1, 2, 3];
        let mut record = vec![22, 3, 3, 0, 13, 11, 0, 0, 9];
        record.extend_from_slice(&body);
        assert_eq!(parse_server_certificate(&record).unwrap(), vec![1, 2, 3]);
    }
}
