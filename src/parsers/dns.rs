use anyhow::{Result, anyhow};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    pub transaction_id: u16,
    pub is_response: bool,
    pub query: Option<String>,
    pub record_type: Option<u16>,
    pub response_code: u8,
    pub answers: Vec<DnsAnswer>,
    pub cname_chain: Vec<String>,
}

/// Parses the DNS header, first question, and answer section. Names are decoded with
/// bounded RFC 1035 compression pointers so response CNAME chains are available.
pub fn parse_dns(bytes: &[u8]) -> Result<DnsSummary> {
    if bytes.len() < 12 {
        return Err(anyhow!("short DNS message"));
    }
    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut p = 12;
    let mut query = None;
    let mut record_type = None;
    for question_index in 0..questions {
        let (name, next) = read_name(bytes, p)?;
        p = next;
        if p + 4 > bytes.len() {
            return Err(anyhow!("truncated DNS question"));
        }
        let ty = u16::from_be_bytes([bytes[p], bytes[p + 1]]);
        p += 4; // type and class
        if question_index == 0 {
            query = Some(name);
            record_type = Some(ty);
        }
    }

    let mut answers = Vec::new();
    let mut cname_chain = Vec::new();
    for _ in 0..answer_count {
        let (name, next) = read_name(bytes, p)?;
        p = next;
        if p + 10 > bytes.len() {
            return Err(anyhow!("truncated DNS answer"));
        }
        let ty = u16::from_be_bytes([bytes[p], bytes[p + 1]]);
        let ttl = u32::from_be_bytes([bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]]);
        let rdlength = u16::from_be_bytes([bytes[p + 8], bytes[p + 9]]) as usize;
        p += 10;
        if p + rdlength > bytes.len() {
            return Err(anyhow!("truncated DNS rdata"));
        }
        let rdata_start = p;
        let value = match ty {
            1 if rdlength == 4 => {
                Ipv4Addr::new(bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]).to_string()
            }
            28 if rdlength == 16 => {
                Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[p..p + 16]).unwrap()).to_string()
            }
            5 | 2 | 12 => read_name(bytes, p)?.0,
            _ => format!("0x{}", hex::encode(&bytes[p..p + rdlength])),
        };
        p = rdata_start + rdlength;
        if ty == 5 {
            if cname_chain.is_empty() {
                cname_chain.push(name.clone());
            }
            cname_chain.push(value.clone());
        }
        answers.push(DnsAnswer {
            name,
            record_type: ty,
            ttl,
            value,
        });
    }

    Ok(DnsSummary {
        transaction_id,
        is_response: flags & 0x8000 != 0,
        query,
        record_type,
        response_code: (flags & 0x000f) as u8,
        answers,
        cname_chain,
    })
}

fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    let mut p = start;
    let mut consumed = None;
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        let n = *bytes.get(p).ok_or_else(|| anyhow!("truncated DNS name"))?;
        if n & 0xc0 == 0xc0 {
            let low = *bytes
                .get(p + 1)
                .ok_or_else(|| anyhow!("truncated DNS pointer"))?;
            let target = (((n & 0x3f) as usize) << 8) | low as usize;
            if target >= bytes.len() || jumps >= 16 {
                return Err(anyhow!("invalid DNS compression pointer"));
            }
            if consumed.is_none() {
                consumed = Some(p + 2);
            }
            p = target;
            jumps += 1;
            continue;
        }
        if n & 0xc0 != 0 || n > 63 {
            return Err(anyhow!("invalid DNS label"));
        }
        p += 1;
        if n == 0 {
            return Ok((labels.join("."), consumed.unwrap_or(p)));
        }
        let end = p + n as usize;
        let label = bytes
            .get(p..end)
            .ok_or_else(|| anyhow!("truncated DNS label"))?;
        labels.push(String::from_utf8_lossy(label).to_string());
        p = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_question() {
        let message = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        let summary = parse_dns(&message).unwrap();
        assert_eq!(summary.query.as_deref(), Some("example.com"));
        assert_eq!(summary.record_type, Some(1));
        assert!(!summary.is_response);
    }

    #[test]
    fn parses_compressed_a_and_cname_answers() {
        let mut message = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        message.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 0, 1, 0, 1,
        ]);
        message.extend_from_slice(&[
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8, 5, b'a', b'l', b'i', b'a', b's', 0xc0, 0x10,
        ]);
        message.extend_from_slice(&[
            5, b'a', b'l', b'i', b'a', b's', 0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2,
            10,
        ]);
        let summary = parse_dns(&message).unwrap();
        assert_eq!(summary.answers.len(), 2);
        assert_eq!(summary.answers[1].value, "192.0.2.10");
        assert_eq!(
            summary.cname_chain,
            vec!["www.example.com", "alias.example.com"]
        );
    }
}
