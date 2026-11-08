//! Unit tests for the derived history metadata (params / extension / cookies / host).

use finch::http_msg::{cookie_count, extension_of, host_only, ip_literal, query_param_count};

#[test]
fn derived_history_metadata() {
    assert_eq!(query_param_count("/a?x=1&y=2"), 2);
    assert_eq!(query_param_count("/a?"), 0);
    assert_eq!(query_param_count("/a"), 0);

    assert_eq!(extension_of("/assets/app.css?v=1"), Some("css".into()));
    assert_eq!(extension_of("/index.html"), Some("html".into()));
    assert_eq!(extension_of("/api/v1/items"), None);
    assert_eq!(extension_of("/"), None);

    assert_eq!(host_only("example.com:443"), "example.com");
    assert_eq!(host_only("http://example.com:80/x"), "example.com");
    assert_eq!(host_only("[::1]:443"), "::1");
    assert_eq!(ip_literal("127.0.0.1:8080"), Some("127.0.0.1".into()));
    assert_eq!(ip_literal("example.com:443"), None);

    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=2\r\nCookie: c=3\r\n\r\n";
    assert_eq!(cookie_count(raw), 3);
    assert_eq!(
        cookie_count(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        0
    );
}
