//! Minimal RFC6455 WebSocket frame parsing (capture only — frames are
//! forwarded verbatim by the proxy; this codec exists purely so the UI can
//! display message direction, opcode and payload).

/// WebSocket opcode (RFC6455 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Other(u8),
}

impl WsOpcode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x0 => WsOpcode::Continuation,
            0x1 => WsOpcode::Text,
            0x2 => WsOpcode::Binary,
            0x8 => WsOpcode::Close,
            0x9 => WsOpcode::Ping,
            0xA => WsOpcode::Pong,
            other => WsOpcode::Other(other),
        }
    }

    /// Human readable name for the UI.
    pub fn as_str(self) -> &'static str {
        match self {
            WsOpcode::Continuation => "cont",
            WsOpcode::Text => "text",
            WsOpcode::Binary => "binary",
            WsOpcode::Close => "close",
            WsOpcode::Ping => "ping",
            WsOpcode::Pong => "pong",
            WsOpcode::Other(_) => "other",
        }
    }

    pub fn is_control(self) -> bool {
        matches!(self, WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong)
    }
}

/// One parsed frame. Client->server frames are unmasked here for display;
/// the raw (still masked) bytes stay untouched on the wire.
#[derive(Debug, Clone)]
pub struct Frame {
    pub fin: bool,
    pub opcode: WsOpcode,
    pub payload: Vec<u8>,
    /// Total wire length of the frame (header + payload).
    pub wire_len: usize,
}

#[derive(Debug)]
pub enum ParseError {
    /// Need more bytes to parse a full frame.
    Incomplete,
    /// Protocol violation (RSV bits set, control frame too large, ...).
    Malformed(&'static str),
}

/// Parse a single frame from `buf`. Returns the frame and how many bytes
/// were consumed, or `Incomplete` if more data is required.
pub fn parse_frame(buf: &[u8]) -> Result<(Frame, usize), ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::Incomplete);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    let rsv = b0 & 0x70;
    if rsv != 0 {
        return Err(ParseError::Malformed("reserved bits set"));
    }
    let opcode = WsOpcode::from_u8(b0 & 0x0F);
    let masked = b1 & 0x80 != 0;
    let mut len = (b1 & 0x7F) as u64;
    let mut offset = 2usize;
    if len == 126 {
        if buf.len() < offset + 2 {
            return Err(ParseError::Incomplete);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as u64;
        offset += 2;
    } else if len == 127 {
        if buf.len() < offset + 8 {
            return Err(ParseError::Incomplete);
        }
        let mut l = [0u8; 8];
        l.copy_from_slice(&buf[offset..offset + 8]);
        len = u64::from_be_bytes(l);
        offset += 8;
    }
    // Control frames must be <= 125 bytes and carry the FIN bit.
    if opcode.is_control() && (len > 125 || !fin) {
        return Err(ParseError::Malformed("invalid control frame"));
    }
    let mask_key = if masked {
        if buf.len() < offset + 4 {
            return Err(ParseError::Incomplete);
        }
        let key = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        offset += 4;
        Some(key)
    } else {
        None
    };
    let payload_len = len as usize;
    if buf.len() < offset + payload_len {
        return Err(ParseError::Incomplete);
    }
    let mut payload = buf[offset..offset + payload_len].to_vec();
    if let Some(key) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    let wire_len = offset + payload_len;
    Ok((
        Frame {
            fin,
            opcode,
            payload,
            wire_len,
        },
        wire_len,
    ))
}

/// Streaming parser that reassembles fragmented messages into single
/// `DecodedMessage`s (data opcodes) and emits control frames as-is.
#[derive(Default)]
pub struct MessageReader {
    buf: Vec<u8>,
    /// Assembling data message state.
    frag_opcode: Option<WsOpcode>,
    frag_payload: Vec<u8>,
    /// Wire bytes accumulated for the in-flight fragmented message.
    frag_wire: Vec<u8>,
}

/// A fully reassembled message.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub opcode: WsOpcode,
    pub payload: Vec<u8>,
    /// Original wire bytes of the whole message (all its frames), forwarded
    /// verbatim when the message is not modified.
    pub wire: Vec<u8>,
}

impl MessageReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes from the wire and drain every complete message.
    /// Incomplete trailing data is buffered for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Result<Decoded, ParseError>> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match parse_frame(&self.buf) {
                Ok((frame, consumed)) => {
                    let wire = self.buf[..consumed].to_vec();
                    self.buf.drain(..consumed);
                    if frame.opcode.is_control() {
                        out.push(Ok(Decoded {
                            opcode: frame.opcode,
                            payload: frame.payload,
                            wire,
                        }));
                        continue;
                    }
                    match (frame.opcode, self.frag_opcode) {
                        (WsOpcode::Text | WsOpcode::Binary, _) => {
                            if frame.fin {
                                out.push(Ok(Decoded {
                                    opcode: frame.opcode,
                                    payload: frame.payload,
                                    wire,
                                }));
                            } else {
                                self.frag_opcode = Some(frame.opcode);
                                self.frag_payload = frame.payload;
                                self.frag_wire = wire;
                            }
                        }
                        (WsOpcode::Continuation, Some(first)) => {
                            self.frag_payload.extend_from_slice(&frame.payload);
                            self.frag_wire.extend_from_slice(&wire);
                            if frame.fin {
                                out.push(Ok(Decoded {
                                    opcode: first,
                                    payload: std::mem::take(&mut self.frag_payload),
                                    wire: std::mem::take(&mut self.frag_wire),
                                }));
                                self.frag_opcode = None;
                            }
                        }
                        // A proxy must not stall the stream on protocol quirks: emit
                        // the frame as-is (its wire bytes are forwarded verbatim) so
                        // both capture and passthrough stay lossless.
                        (WsOpcode::Continuation, None) => {
                            out.push(Ok(Decoded {
                                opcode: WsOpcode::Continuation,
                                payload: frame.payload,
                                wire,
                            }));
                        }
                        (_, None) => {
                            // New data frame while a fragment is assembling: emit the
                            // assembled part first, then this frame on its own.
                            if let Some(first) = self.frag_opcode.take() {
                                out.push(Ok(Decoded {
                                    opcode: first,
                                    payload: std::mem::take(&mut self.frag_payload),
                                    wire: std::mem::take(&mut self.frag_wire),
                                }));
                            }
                            out.push(Ok(Decoded {
                                opcode: frame.opcode,
                                payload: frame.payload,
                                wire,
                            }));
                        }
                        // Control frames were handled above; nothing else can land here.
                        _ => {}
                    }
                }
                Err(e) => {
                    if matches!(e, ParseError::Incomplete) {
                        // Cap the buffer so a hostile peer cannot exhaust memory.
                        const MAX_BUF: usize = 64 * 1024 * 1024;
                        if self.buf.len() > MAX_BUF {
                            self.buf.clear();
                            out.push(Err(ParseError::Malformed("frame too large")));
                        }
                    } else {
                        // Skip the unparseable header to avoid a poison-pill stream.
                        self.buf.clear();
                    }
                    break;
                }
            }
        }
        out
    }
}

/// True when an HTTP request is a WebSocket upgrade (RFC6455 §4.1).
pub fn is_upgrade_request(method: &http::Method, headers: &http::HeaderMap) -> bool {
    if method != http::Method::GET {
        return false;
    }
    let is_upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let has_connection = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.to_ascii_lowercase()
                .split(',')
                .any(|p| p.trim() == "upgrade")
        })
        .unwrap_or(false);
    is_upgrade && has_connection
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let mask = [0x11, 0x22, 0x33, 0x44];
        if payload.len() < 126 {
            out.push(0x80 | payload.len() as u8);
        } else {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        out
    }

    #[test]
    fn parses_masked_text_frame() {
        let raw = mask_frame(0x1, b"hello", true);
        let (frame, n) = parse_frame(&raw).unwrap();
        assert_eq!(n, raw.len());
        assert!(frame.fin);
        assert_eq!(frame.opcode, WsOpcode::Text);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn incomplete_returns_error() {
        let raw = mask_frame(0x1, b"hello", true);
        assert!(matches!(
            parse_frame(&raw[..3]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn reassembles_fragments() {
        let mut reader = MessageReader::new();
        let mut raw = mask_frame(0x1, b"foo", false);
        raw.extend(mask_frame(0x0, b"bar", true));
        raw.extend(mask_frame(0x9, b"ping", true));
        let msgs = reader.feed(&raw);
        assert_eq!(msgs.len(), 2);
        let first = msgs[0].as_ref().unwrap();
        assert_eq!(first.opcode, WsOpcode::Text);
        assert_eq!(first.payload, b"foobar");
        let second = msgs[1].as_ref().unwrap();
        assert_eq!(second.opcode, WsOpcode::Ping);
    }

    #[test]
    fn detects_upgrade() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        assert!(is_upgrade_request(&http::Method::GET, &headers));
        assert!(!is_upgrade_request(&http::Method::POST, &headers));
        headers.remove(http::header::CONNECTION);
        assert!(!is_upgrade_request(&http::Method::GET, &headers));
    }
}

/// Encode a message as a single frame. `mask` must be true for
/// client->origin traffic (RFC6455: all frames from the client are masked).
pub fn encode_frame(opcode: WsOpcode, payload: &[u8], mask: bool, mask_key: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(
        0x80 | (match opcode {
            WsOpcode::Continuation => 0x0,
            WsOpcode::Text => 0x1,
            WsOpcode::Binary => 0x2,
            WsOpcode::Close => 0x8,
            WsOpcode::Ping => 0x9,
            WsOpcode::Pong => 0xA,
            WsOpcode::Other(v) => v & 0x0F,
        }),
    );
    let len_flag = if mask { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(len_flag | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(len_flag | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(len_flag | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if mask {
        out.extend_from_slice(&mask_key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask_key[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}
