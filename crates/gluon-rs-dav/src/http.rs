use std::collections::HashMap;

use crate::error::{DavError, Result};

const MAX_REQUEST_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavResponse {
    pub status: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl DavResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("HTTP/1.1 {}\r\n", self.status).as_bytes());

        let mut has_length = false;
        let mut has_connection = false;
        for (name, value) in &self.headers {
            has_length |= name.eq_ignore_ascii_case("content-length");
            has_connection |= name.eq_ignore_ascii_case("connection");
            out.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        if !has_length {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        if !has_connection {
            out.extend_from_slice(b"Connection: close\r\n");
        }

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

pub fn parse_request_head(buffer: &[u8]) -> Result<DavRequest> {
    let head =
        std::str::from_utf8(buffer).map_err(|_| DavError::InvalidRequest("non-utf8 head"))?;
    let mut lines = head.split("\r\n");

    let request_line = lines
        .next()
        .ok_or(DavError::InvalidRequest("missing request line"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(DavError::InvalidRequest("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(DavError::InvalidRequest("missing path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or(DavError::InvalidRequest("missing http version"))?
        .to_string();

    if parts.next().is_some() {
        return Err(DavError::InvalidRequest("malformed request line"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(DavError::InvalidRequest("malformed header line"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok(DavRequest {
        method,
        path,
        version,
        headers,
    })
}

pub fn split_head_from_buffer(buffer: &[u8]) -> Result<usize> {
    let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buffer.len() >= MAX_REQUEST_SIZE {
            return Err(DavError::InvalidRequest("request too large"));
        }
        return Err(DavError::InvalidRequest("incomplete headers"));
    };

    Ok(end + 4)
}

pub fn not_implemented_response() -> DavResponse {
    DavResponse {
        status: "501 Not Implemented",
        headers: vec![
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
            (
                "DAV",
                "1, 2, calendar-access, addressbook, sync-collection".to_string(),
            ),
            (
                "Allow",
                "OPTIONS, PROPFIND, PROPPATCH, REPORT, GET, HEAD, PUT, DELETE".to_string(),
            ),
        ],
        body: b"DAV support is not implemented yet\n".to_vec(),
    }
}

pub fn options_response() -> DavResponse {
    DavResponse {
        status: "200 OK",
        headers: vec![
            (
                "DAV",
                "1, 2, calendar-access, addressbook, sync-collection, webdav-push".to_string(),
            ),
            (
                "Allow",
                "OPTIONS, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, GET, HEAD, PUT, DELETE, POST"
                    .to_string(),
            ),
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ],
        body: b"OpenProton DAV\n".to_vec(),
    }
}

pub fn unauthorized_response() -> DavResponse {
    DavResponse {
        status: "401 Unauthorized",
        headers: vec![
            (
                "WWW-Authenticate",
                "Basic realm=\"openproton-bridge\"".to_string(),
            ),
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ],
        body: b"authentication required\n".to_vec(),
    }
}

pub fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

pub fn forbidden_response() -> DavResponse {
    DavResponse {
        status: "403 Forbidden",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"forbidden\n".to_vec(),
    }
}

pub fn service_unavailable_response() -> DavResponse {
    DavResponse {
        status: "503 Service Unavailable",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"account store unavailable\n".to_vec(),
    }
}

pub fn payload_too_large_response() -> DavResponse {
    DavResponse {
        status: "413 Payload Too Large",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"request body too large\n".to_vec(),
    }
}

pub fn finite_depth_required_response() -> DavResponse {
    DavResponse {
        status: "403 Forbidden",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: br#"<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:"><d:propfind-finite-depth/></d:error>"#.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::{not_implemented_response, parse_request_head};

    #[test]
    fn parse_request_head_extracts_method_path_and_headers() {
        let raw = b"PROPFIND /dav/principals/me/ HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\n\r\n";
        let request = parse_request_head(raw).expect("request head should parse");

        assert_eq!(request.method, "PROPFIND");
        assert_eq!(request.path, "/dav/principals/me/");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(
            request.headers.get("host").map(String::as_str),
            Some("localhost")
        );
        assert_eq!(request.headers.get("depth").map(String::as_str), Some("1"));
    }

    #[test]
    fn not_implemented_response_serializes_501() {
        let response = not_implemented_response();
        let wire = String::from_utf8(response.to_bytes()).expect("valid utf8 response");

        assert!(wire.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
        assert!(wire.contains("DAV: 1, 2, calendar-access, addressbook, sync-collection\r\n"));
        assert!(wire.contains("DAV support is not implemented yet"));
    }
}
