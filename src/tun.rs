//! TUN capture mode: a virtual network adapter (wintun) that pulls the
//! machine's IPv4 traffic through a userspace TCP/IP stack, attributes each
//! flow to the process that owns it, and forwards flows of *matching*
//! processes through Finch's local proxy so they show up in HTTP history and
//! can be intercepted. All other traffic (and every UDP flow) is relayed
//! directly via the physical interface.
//!
//! Mechanics:
//! - Routes `0.0.0.0/1` + `128.0.0.0/1` (more specific than the default
//!   route) steer IPv4 into the TUN adapter without touching the default
//!   route entry itself.
//! - The physical interface address is captured *before* the routes go up so
//!   direct relays can bind to it — otherwise Finch's own upstream
//!   connections would loop back into the TUN.
//! - Transparent TCP cannot be piped into the proxy listener verbatim (it
//!   only speaks CONNECT / plain HTTP), so matched flows go through a small
//!   shim that sniffs TLS SNI / HTTP Host, dials `127.0.0.1:<proxy>` with a
//!   CONNECT, and then pipes bytes both ways.
//! - The shim records the local port of its proxy connection in
//!   `SharedState::tun_proc_map`; the interceptor maps that back to the
//!   process name when it builds the history entry.

use crate::state::SharedState;

/// Capture filter: empty = every process; otherwise case-insensitive
/// substring match of any entry against the process name.
pub fn process_matches(filter: &[String], proc_name: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let n = proc_name.to_lowercase();
    filter
        .iter()
        .map(|f| f.trim().to_lowercase())
        .any(|f| !f.is_empty() && n.contains(&f))
}

/// True when the process name belongs to Finch itself. Finch's own upstream
/// connections must never be steered through the proxy path (infinite loop).
pub fn is_self_process(proc_name: &str) -> bool {
    let self_names: Vec<String> = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .map(|n| {
            let lower = n.to_lowercase();
            let mut v = vec![lower.clone()];
            let stem = lower.trim_end_matches(".exe").to_string();
            v.push(stem);
            v
        })
        .unwrap_or_default();
    let n = proc_name.to_lowercase();
    self_names.iter().any(|s| !s.is_empty() && s == &n)
}

/// Running processes that currently own network sockets (TCP/UDP, any
/// state), deduplicated by PID and sorted by name. Finch itself is excluded
/// (hijacking it is meaningless and forbidden in the engine). Empty on
/// non-Windows platforms.
pub fn list_network_processes() -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        use std::collections::BTreeSet;
        let af = netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6;
        let proto = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;
        let Ok(rows) = netstat2::get_sockets_info(af, proto) else {
            return Vec::new();
        };
        let pids: BTreeSet<u32> = rows
            .iter()
            .filter_map(|si| si.associated_pids.first().copied())
            .filter(|pid| *pid > 4) // skip System / Idle
            .collect();
        let self_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()));
        let mut out: Vec<(u32, String)> = pids
            .into_iter()
            .filter_map(|pid| {
                let name = engine::pid_to_name(pid)?;
                if self_name.as_deref() == Some(&name.to_lowercase()) {
                    return None;
                }
                Some((pid, name))
            })
            .collect();
        out.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()).then(a.0.cmp(&b.0)));
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Whether the current process runs with administrator rights.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        engine::is_elevated()
    }
    #[cfg(not(windows))]
    {
        // Unix needs root (or CAP_NET_ADMIN) for TUN; the kernel enforces
        // it and the error surfaces from the device open anyway.
        false
    }
}

/// Relaunch Finch elevated (UAC) with `extra_arg` appended to the command
/// line. The current instance should exit right after on success so the new
/// one can take over the listener port.
pub fn relaunch_elevated(extra_arg: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let exe =
            std::env::current_exe().map_err(|e| format!("cannot resolve finch.exe: {e}"))?;
        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let params: Vec<u16> = format!("{extra_arg}\0").encode_utf16().collect();
        let ret = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns a value > 32 on success.
        if ret as isize > 32 {
            Ok(())
        } else if ret as isize == 0 {
            Err("UAC prompt was cancelled — TUN not enabled".into())
        } else {
            Err(format!(
                "elevation failed (ShellExecuteW error {}); start Finch as administrator instead",
                ret as isize
            ))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = extra_arg;
        Err("elevation relaunch is only implemented on Windows".into())
    }
}

// ---------------------------------------------------------------- API

/// Enable TUN capture. Requires administrator on Windows.
pub fn start(shared: std::sync::Arc<SharedState>) -> Result<(), String> {
    if shared.tun_enabled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("TUN mode is already running".into());
    }
    #[cfg(windows)]
    {
        engine::start(shared)
    }
    #[cfg(not(windows))]
    {
        let _ = shared;
        Err("TUN mode is currently only implemented on Windows (wintun)".into())
    }
}

/// Disable TUN capture and remove the routes.
pub fn stop(shared: std::sync::Arc<SharedState>) {
    #[cfg(windows)]
    engine::stop(&shared);
    #[cfg(not(windows))]
    {
        let _ = shared;
    }
    shared
        .tun_enabled
        .store(false, std::sync::atomic::Ordering::Relaxed);
}

// ---------------------------------------------------------------- engine

#[cfg(windows)]
mod engine {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    use ipstack::{IpStack, IpStackConfig, IpStackStream};
    use route_manager::{Route, RouteManager};
    use tokio::io::copy_bidirectional;
    use tokio::net::TcpStream;
    use tokio::sync::watch;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{is_self_process, process_matches};
    use crate::state::SharedState;

    const TUN_NAME: &str = "FinchTun";
    const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 2);
    const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
    const MTU: u16 = 65535;
    /// Wintun release shipped on first use (official signed build).
    const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    struct RuntimeHandle {
        stop_tx: watch::Sender<bool>,
        routes: Vec<Route>,
    }

    static RUNTIME: std::sync::Mutex<Option<RuntimeHandle>> = std::sync::Mutex::new(None);

    /// Flow attribution snapshot: (proto, local ip, local port, remote port)
    /// -> process name. Refreshed every ~300 ms from the OS socket tables.
    type ProcSnapshot = Arc<RwLock<HashMap<(u8, IpAddr, u16, u16), String>>>;

    pub fn start(shared: Arc<SharedState>) -> Result<(), String> {
        // Single-flight guard.
        {
            let mut rt = RUNTIME.lock().unwrap();
            if rt.is_some() {
                return Err("TUN mode is already running".into());
            }

            if !is_elevated() {
                return Err(
                    "TUN mode requires administrator rights. Restart Finch as administrator."
                        .into(),
                );
            }

            let dll = ensure_wintun_dll()?;

            // The physical address must be captured BEFORE the TUN routes go
            // up; afterwards a probe socket would resolve to the TUN itself.
            let phys_ip = detect_physical_ipv4()
                .ok_or("failed to detect the physical interface address")?;

            let mut config = tun::Configuration::default();
            config
                .tun_name(TUN_NAME)
                .address(TUN_ADDR)
                .netmask(TUN_NETMASK)
                .mtu(MTU)
                .up();
            let dll_for_config = dll.clone();
            config.platform_config(move |p| {
                p.wintun_file(dll_for_config.to_string_lossy().to_string());
            });
            let device = tun::AsyncDevice::new(
                tun::create(&config)
                    .map_err(|e| format!("failed to create TUN adapter: {e}"))?,
            )
            .map_err(|e| format!("failed to open TUN adapter: {e}"))?;

            // The /1 routes must be scoped to the TUN interface itself: a
            // gateway-only route cannot be resolved by CreateIpForwardEntry2
            // (ERROR_FILE_NOT_FOUND) because the gateway is not tied to an
            // interface index. The freshly assigned adapter address produced
            // an on-link 10.10.0.0/24 route — look it up and reuse its
            // interface index (same approach as mihomo's auto-route).
            let mut probe = RouteManager::new().map_err(|e| format!("route manager: {e}"))?;
            let tun_if_index = {
                let mut found = None;
                for _ in 0..10 {
                    if let Ok(list) = probe.list() {
                        if let Some(r) = list.iter().find(|r| {
                            r.destination() == IpAddr::from([10, 10, 0, 0]) && r.prefix() == 24
                        }) {
                            found = r.if_index();
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                found.ok_or_else(|| {
                    "could not locate the FinchTun interface (no on-link 10.10.0.0/24 route)".to_string()
                })?
            };

            // Split default route: two /1s beat the default /0 regardless of
            // metric, so we never touch the default route entry itself.
            let routes: Vec<Route> = vec![
                Route::new(IpAddr::from([0, 0, 0, 0]), 1).with_if_index(tun_if_index),
                Route::new(IpAddr::from([128, 0, 0, 0]), 1).with_if_index(tun_if_index),
            ];
            for r in &routes {
                probe.add(r).map_err(|e| {
                    format!("failed to add TUN route {r}: {e} (administrator required)")
                })?;
            }

            let (stop_tx, stop_rx) = watch::channel(false);
            *rt = Some(RuntimeHandle { stop_tx, routes });
            drop(rt);

            let proxy_port = shared.settings.lock().unwrap().listen_port;
            let snapshot: ProcSnapshot = Arc::new(RwLock::new(HashMap::new()));
            spawn_table_poller(snapshot.clone(), stop_rx.clone());
            crate::app::runtime().spawn(run_stack(
                shared.clone(),
                device,
                snapshot,
                stop_rx,
                phys_ip,
                proxy_port,
            ));

            *shared.tun_status.lock().unwrap() = format!(
                "running — adapter {TUN_NAME} {TUN_ADDR}/24, relays bound to {phys_ip}"
            );
            shared.set_status(format!("TUN mode enabled ({TUN_ADDR}/24)"));
            shared
                .tun_enabled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    pub fn stop(shared: &Arc<SharedState>) {
        let handle = RUNTIME.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.stop_tx.send(true);
            let mut manager = RouteManager::new().ok();
            for r in &h.routes {
                if let Some(m) = manager.as_mut() {
                    let _ = m.delete(r);
                }
            }
            shared.set_status("TUN mode disabled");
        }
        *shared.tun_status.lock().unwrap() = String::new();
        shared
            .tun_enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    // ------------------------------------------------------------ stack loop

    async fn run_stack(
        shared: Arc<SharedState>,
        device: tun::AsyncDevice,
        snapshot: ProcSnapshot,
        mut stop_rx: watch::Receiver<bool>,
        phys_ip: Ipv4Addr,
        proxy_port: u16,
    ) {
        let mut config = IpStackConfig::default();
        let _ = config.mtu(MTU);
        let mut stack = IpStack::new(config, device);

        loop {
            let stream = tokio::select! {
                _ = stop_rx.changed() => break,
                s = stack.accept() => match s {
                    Ok(s) => s,
                    Err(e) => {
                        *shared.tun_status.lock().unwrap() = format!("stack stopped: {e}");
                        break;
                    }
                }
            };
            match stream {
                IpStackStream::Tcp(tcp) => {
                    let shared = shared.clone();
                    let snapshot = snapshot.clone();
                    tokio::spawn(handle_tcp(
                        tcp, shared, snapshot, phys_ip, proxy_port,
                    ));
                }
                IpStackStream::Udp(udp) => {
                    let phys = phys_ip;
                    tokio::spawn(async move { relay_udp(udp, phys).await });
                }
                IpStackStream::UnknownTransport(u) => {
                    // ICMP echo: answer in-stack so ping still works.
                    tokio::spawn(async move { icmp_echo(u).await });
                }
                IpStackStream::UnknownNetwork(_) => {}
            }
        }
        let _ = stop_rx;
    }

    async fn handle_tcp(
        tcp: ipstack::IpStackTcpStream,
        shared: Arc<SharedState>,
        snapshot: ProcSnapshot,
        phys_ip: Ipv4Addr,
        proxy_port: u16,
    ) {
        let dst = tcp.local_addr();
        let client = tcp.peer_addr();
        let proc_name = lookup_process(&snapshot, 1, client, dst.port());

        // Decide the path: Finch itself and unknown/filtered-out processes
        // are relayed directly (bound to the physical interface so they do
        // not loop back into the TUN); matching processes go through the
        // local proxy.
        let filter = shared.settings.lock().unwrap().tun_process_filter.clone();
        let capture = match &proc_name {
            Some(name) => !is_self_process(name) && process_matches(&filter, name),
            None => false,
        };

        if capture {
            if let Err(e) = proxy_flow(tcp, &shared, proc_name.as_deref(), dst, proxy_port).await {
                tracing::debug!("[TUN] proxied flow to {dst} failed: {e}");
            }
        } else {
            use tokio::io::AsyncWriteExt;
            let mut up = match dial_direct(dst, phys_ip) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("[TUN] direct dial {dst} failed: {e}");
                    return;
                }
            };
            let mut tcp = tcp;
            let _ = copy_bidirectional(&mut tcp, &mut up).await;
            let _ = up.shutdown().await;
        }
    }

    /// Shim: sniff SNI/Host, CONNECT to the local proxy, then pipe.
    async fn proxy_flow(
        mut tcp: ipstack::IpStackTcpStream,
        shared: &Arc<SharedState>,
        proc_name: Option<&str>,
        dst: SocketAddr,
        proxy_port: u16,
    ) -> Result<(), String> {
        let (target, buffered) = sniff_target(&mut tcp, dst).await?;

        let mut proxy_conn = TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .map_err(|e| format!("connect proxy: {e}"))?;

        // Attribute the proxy connection: the interceptor later maps the
        // client source port (which is this connection's local port) back to
        // the process name.
        if let (Some(name), Ok(local)) = (proc_name, proxy_conn.local_addr()) {
            let mut map = shared.tun_proc_map.lock().unwrap();
            map.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(120));
            if map.len() > 4096 {
                map.clear();
            }
            map.insert(local.port(), (name.to_string(), Instant::now()));
        }

        let req = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: FinchTun/0.1\r\n\r\n"
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        proxy_conn
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("send CONNECT: {e}"))?;
        // Read the proxy's response head (200 or an error like 403); the
        // bytes after the head belong to the tunnelled stream.
        let mut head = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            let n = proxy_conn
                .read(&mut byte)
                .await
                .map_err(|e| format!("read CONNECT response: {e}"))?;
            if n == 0 {
                return Err("proxy closed during CONNECT".into());
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 8192 {
                return Err("CONNECT response too large".into());
            }
        }

        proxy_conn
            .write_all(&buffered)
            .await
            .map_err(|e| format!("forward buffered bytes: {e}"))?;

        let _ = copy_bidirectional(&mut tcp, &mut proxy_conn).await;
        let _ = proxy_conn.shutdown().await;
        Ok(())
    }

    /// Relay straight to the destination, bound to the physical interface.
    /// Blocking connect inside a per-flow task is acceptable (one small
    /// stall per flow); the socket goes non-blocking before handing it to
    /// tokio.
    fn dial_direct(dst: SocketAddr, bind_ip: Ipv4Addr) -> Result<TcpStream, String> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        let sock = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| e.to_string())?;
        let bind: SocketAddr = if dst.is_ipv4() {
            SocketAddr::new(IpAddr::from(bind_ip.octets()), 0)
        } else {
            SocketAddr::new(IpAddr::from([0u16; 8]), 0)
        };
        sock.bind(&SockAddr::from(bind)).map_err(|e| e.to_string())?;
        sock.connect(&SockAddr::from(dst)).map_err(|e| e.to_string())?;
        let s: std::net::TcpStream = sock.into();
        s.set_nonblocking(true).map_err(|e| e.to_string())?;
        TcpStream::from_std(s).map_err(|e| e.to_string())
    }

    /// UDP NAT: every UDP flow is relayed directly (Finch's proxy has no UDP
    /// path). Covers DNS and QUIC; process attribution is not recorded.
    async fn relay_udp(
        mut udp: ipstack::IpStackUdpStream,
        phys_ip: Ipv4Addr,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dst = udp.local_addr();
        let bind: SocketAddr = if dst.is_ipv4() {
            SocketAddr::new(IpAddr::from(phys_ip.octets()), 0)
        } else {
            SocketAddr::new(IpAddr::from([0u16; 8]), 0)
        };
        let Ok(sock) = socket2::Socket::new(
            socket2::Domain::for_address(dst),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) else {
            return;
        };
        if sock.bind(&socket2::SockAddr::from(bind)).is_err()
            || sock.connect(&socket2::SockAddr::from(dst)).is_err()
        {
            return;
        }
        sock.set_nonblocking(true).ok();
        let Ok(up) = tokio::net::UdpSocket::from_std(sock.into()) else {
            return;
        };
        // Datagram-ish piping: read payload from the TUN app, send it out;
        // any reply datagram is written back into the stack.
        let mut to_net = vec![0u8; 65535];
        let mut to_app = vec![0u8; 65535];
        loop {
            tokio::select! {
                r = udp.read(&mut to_net) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if up.send(&to_net[..n]).await.is_err() { break; } }
                },
                r = up.recv(&mut to_app) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if udp.write_all(&to_app[..n]).await.is_err() { break; } }
                },
            }
        }
    }

    async fn icmp_echo(u: ipstack::IpStackUnknownTransport) {
        // Only echo request/reply for ICMP v4.
        if u.src_addr().is_ipv4() && u.ip_protocol() == ipstack::IpNumber::ICMP {
            let payload: Vec<u8> = u.payload().into();
            if payload.len() >= 8 && payload[0] == 8 {
                // Echo request -> build reply: flip type, clear checksum,
                // recompute over the whole packet.
                let mut reply = payload;
                reply[0] = 0;
                reply[2] = 0;
                reply[3] = 0;
                let sum = checksum(&reply);
                reply[2] = (sum >> 8) as u8;
                reply[3] = (sum & 0xff) as u8;
                let _ = u.send(reply);
            }
        }
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in data.chunks(2) {
            let w = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
            sum += w as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    // ------------------------------------------------------------ sniffing

    /// Read just enough of the stream to learn where it wants to go.
    /// Returns the CONNECT target (`host:port`) plus any bytes already
    /// consumed (they must be replayed into the tunnel).
    async fn sniff_target(
        tcp: &mut ipstack::IpStackTcpStream,
        dst: SocketAddr,
    ) -> Result<(String, Vec<u8>), String> {
        use tokio::io::AsyncReadExt;
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];

        // Wait for the first bytes (client-speaks-first protocols).
        while buf.len() < 2 {
            let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut chunk))
                .await
                .map_err(|_| "timeout waiting for first bytes".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("client closed before sending data".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        // TLS: record type 0x16, version 0x03 xx. Read the full record and
        // pull the SNI out of the ClientHello.
        if buf[0] == 0x16 && buf[1] == 0x03 {
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let total = 5 + rec_len;
            while buf.len() < total.min(64 * 1024) {
                let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut chunk))
                    .await
                    .map_err(|_| "timeout reading ClientHello".to_string())?
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let host = sni_from_client_hello(&buf)
                .unwrap_or_else(|| dst.ip().to_string());
            let target = format!("{}:{}", host.trim_end_matches('.'), dst.port());
            return Ok((target, buf));
        }

        // Plain HTTP: read until end of request head, then use the Host
        // header. Anything else is a non-HTTP protocol -> relay directly.
        loop {
            if let Some(pos) = find(bufwindows(&buf), b"\r\n\r\n") {
                let head = &buf[..pos];
                if let Some(host) = host_from_http_head(head) {
                    let (h, p) = split_host_port(&host, dst.port());
                    return Ok((format!("{h}:{p}"), buf));
                }
                // HTTP-ish but no Host header: fall back to the literal
                // destination address.
                let target = format!("{}:{}", dst.ip(), dst.port());
                return Ok((target, buf));
            }
            // A first line that doesn't smell like HTTP means "some other
            // protocol" — stop reading, relay raw.
            if find(bufwindows(&buf), b"\n").is_some() && !looks_like_http_head(&buf) {
                return Err(NOT_HTTP.into());
            }
            if buf.len() > 64 * 1024 {
                return Err(NOT_HTTP.into());
            }
            let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut chunk))
                .await
                .map_err(|_| NOT_HTTP.to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err(NOT_HTTP.into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    const NOT_HTTP: &str = "\x00not-http";

    fn bufwindows(b: &[u8]) -> &[u8] {
        b
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
    }

    fn looks_like_http_head(buf: &[u8]) -> bool {
        let line_end = find(buf, b"\n").unwrap_or(buf.len());
        let line = &buf[..line_end];
        let s = String::from_utf8_lossy(line);
        let mut parts = s.split_whitespace();
        let method = parts.next().unwrap_or("");
        parts.next().is_some()
            && parts.next().map(|v| v.starts_with("HTTP/")).unwrap_or(false)
            && method
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '-')
            && !method.is_empty()
    }

    pub(crate) fn host_from_http_head(head: &[u8]) -> Option<String> {
        let s = String::from_utf8_lossy(head);
        for line in s.split("\r\n").skip(1) {
            if let Some(v) = line.strip_prefix("Host:").or(line.strip_prefix("host:")) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    pub(crate) fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
        if let Some(rest) = host.strip_prefix('[') {
            // [v6]:port
            if let Some((h, p)) = rest.split_once(']') {
                let port = p.trim_start_matches(':').parse().unwrap_or(default_port);
                return (h.to_string(), port);
            }
        }
        match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h.to_string(), p.parse().unwrap_or(default_port))
            }
            _ => (host.to_string(), default_port),
        }
    }

    /// Extract the SNI hostname from a (possibly partial) ClientHello record.
    pub(crate) fn sni_from_client_hello(b: &[u8]) -> Option<String> {
        if b.len() < 5 || b[0] != 0x16 {
            return None;
        }
        let rec_len = u16::from_be_bytes([b[3], b[4]]) as usize;
        let end = (5 + rec_len).min(b.len());
        let mut p = 5usize;
        if p >= end || b[p] != 0x01 {
            return None; // not a ClientHello
        }
        p += 4; // handshake type + length
        p += 2 + 32; // client version + random
        if p >= end {
            return None;
        }
        let sid = b[p] as usize;
        p += 1 + sid;
        if p + 2 > end {
            return None;
        }
        let cs = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2 + cs;
        if p >= end {
            return None;
        }
        let comp = b[p] as usize;
        p += 1 + comp;
        if p + 2 > end {
            return None;
        }
        let ext_total = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        let ext_end = (p + ext_total).min(end);
        while p + 4 <= ext_end {
            let et = u16::from_be_bytes([b[p], b[p + 1]]);
            let el = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
            p += 4;
            if p + el > ext_end {
                break;
            }
            if et == 0x0000 {
                // server_name list
                let mut q = p;
                if q + 2 > p + el {
                    return None;
                }
                let list_len = u16::from_be_bytes([b[q], b[q + 1]]) as usize;
                q += 2;
                let list_end = (q + list_len).min(p + el);
                if q + 3 <= list_end && b[q] == 0 {
                    let nl = u16::from_be_bytes([b[q + 1], b[q + 2]]) as usize;
                    q += 3;
                    if q + nl <= list_end {
                        return String::from_utf8(b[q..q + nl].to_vec()).ok();
                    }
                }
                return None;
            }
            p += el;
        }
        None
    }

    // ------------------------------------------------------- process lookup

    fn spawn_table_poller(snapshot: ProcSnapshot, mut stop_rx: watch::Receiver<bool>) {
        crate::app::runtime().spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {
                        let af = netstat2::AddressFamilyFlags::IPV4;
                        let proto =
                            netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;
                        if let Ok(rows) = netstat2::get_sockets_info(af, proto) {
                            let mut map = HashMap::with_capacity(rows.len());
                            for si in rows {
                                let Some(pid) = si.associated_pids.first().copied() else {
                                    continue;
                                };
                                let Some(name) = pid_to_name(pid) else {
                                    continue;
                                };
                                match si.protocol_socket_info {
                                    netstat2::ProtocolSocketInfo::Tcp(t) => {
                                        map.insert(
                                            (1u8, IpAddr::from(t.local_addr), t.local_port, t.remote_port),
                                            name,
                                        );
                                    }
                                    netstat2::ProtocolSocketInfo::Udp(u) => {
                                        map.insert(
                                            (2u8, IpAddr::from(u.local_addr), u.local_port, 0),
                                            name,
                                        );
                                    }
                                }
                            }
                            if let Ok(mut w) = snapshot.write() {
                                *w = map;
                            }
                        }
                    }
                }
            }
        });
    }

    fn lookup_process(
        snapshot: &ProcSnapshot,
        proto: u8,
        client: SocketAddr,
        dst_port: u16,
    ) -> Option<String> {
        let snap = snapshot.read().ok()?;
        snap.get(&(proto, client.ip(), client.port(), dst_port))
            .cloned()
            .or_else(|| {
                // TCP: the SYN row may still show remote port 0 in the table
                // snapshot; fall back to a wildcard-remote lookup.
                snap.get(&(proto, client.ip(), client.port(), 0))
                    .cloned()
            })
    }

    pub(crate) fn pid_to_name(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &mut len,
            );
            CloseHandle(handle);
            if ok == 0 || len == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            path.rsplit(['\\', '/']).next().map(|s| s.to_string())
        }
    }

    // ------------------------------------------------------------- helpers

    pub(crate) fn is_elevated() -> bool {
        // shell32 IsUserAnAdmin: simple and reliable for our purpose.
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }

    fn detect_physical_ipv4() -> Option<Ipv4Addr> {
        // Connect a UDP socket to a public address (no packets are sent) and
        // read back the locally chosen source address: that is the interface
        // the default route currently uses.
        let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        s.connect("8.8.8.8:53").ok()?;
        match s.local_addr().ok()?.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    fn dll_cache_dir() -> Option<PathBuf> {
        std::env::var("LOCALAPPDATA").ok().map(|d| PathBuf::from(d).join("Finch"))
    }

    fn ensure_wintun_dll() -> Result<PathBuf, String> {
        let mut candidates = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll"));
                candidates.push(dir.join("wintun").join("amd64").join("wintun.dll"));
            }
        }
        let cache = dll_cache_dir().ok_or("cannot resolve %LOCALAPPDATA%")?;
        candidates.push(cache.join("wintun.dll"));
        for c in &candidates {
            if c.is_file() {
                return Ok(c.clone());
            }
        }
        // Not found: download the official build and cache it.
        std::fs::create_dir_all(&cache).map_err(|e| format!("create cache dir: {e}"))?;
        let req = format!(
            "GET /builds/wintun-0.14.1.zip HTTP/1.1\r\nHost: www.wintun.net\r\nUser-Agent: Finch/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let res = { let rt = crate::app::runtime(); rt.block_on(async {
            crate::engine::send_raw(
                "https",
                "www.wintun.net",
                req.as_bytes(),
                Duration::from_secs(60),
            )
            .await
        }) };
        if let Some(e) = res.error {
            return Err(format!(
                "wintun.dll not found and download failed: {e}. Put wintun.dll (from {WINTUN_URL}) next to finch.exe and retry."
            ));
        }
        if res.status != Some(200) {
            return Err(format!(
                "wintun.net returned HTTP {} — download wintun.dll manually from {WINTUN_URL} and place it next to finch.exe",
                res.status.unwrap_or(0)
            ));
        }
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        };
        let wanted_amd64 = format!("bin/{arch}/wintun.dll");
        let mut archive =
            zip::ZipArchive::new(Cursor::new(res.body)).map_err(|e| format!("bad wintun zip: {e}"))?;
        let mut names = Vec::new();
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index_raw(i) {
                names.push(f.name().to_string());
            }
        }
        let matched = names
            .iter()
            .find(|n| n.replace('\\', "/").ends_with(&wanted_amd64))
            .cloned()
            .or_else(|| {
                names
                    .iter()
                    .find(|n| n.replace('\\', "/").ends_with("wintun.dll"))
                    .cloned()
            })
            .ok_or("wintun.dll not inside the downloaded zip")?;
        let mut f = archive
            .by_name(&matched)
            .map_err(|e| format!("zip entry {matched}: {e}"))?;
        let mut bytes = Vec::with_capacity(f.size() as usize);
        std::io::Read::read_to_end(&mut f, &mut bytes).map_err(|e| e.to_string())?;
        let out = cache.join("wintun.dll");
        std::fs::write(&out, &bytes).map_err(|e| format!("write wintun.dll: {e}"))?;
        Ok(out)
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matching() {
        assert!(process_matches(&[], "anything.exe"));
        assert!(process_matches(
            &[("chrome".into())],
            "C:\\apps\\Chrome.exe"
        ));
        assert!(!process_matches(&["chrome".into()], "firefox.exe"));
        assert!(!process_matches(&["  ".into()], "chrome.exe"));
    }

    #[test]
    fn self_detection() {
        let name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
            .unwrap_or_default();
        assert!(is_self_process(&name));
        assert!(!is_self_process("definitely-not-finch.exe"));
    }

    /// Build a minimal TLS ClientHello carrying server_name "example.com".
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut exts = Vec::new();
        // server_name extension
        let mut list = vec![0u8]; // host_name type
        list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        list.extend_from_slice(sni.as_bytes());
        let mut ext = 0x0000u16.to_be_bytes().to_vec();
        // Extension data length covers the 2-byte list length prefix too.
        ext.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        exts.extend_from_slice(&ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // one cipher
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01u8]; // client_hello
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[cfg(windows)]
    #[test]
    fn sni_parse() {
        let hello = build_client_hello("example.com");
        assert_eq!(
            engine::sni_from_client_hello(&hello).as_deref(),
            Some("example.com")
        );
        assert_eq!(engine::sni_from_client_hello(b"\x17\x03\x03"), None);
    }

    #[cfg(windows)]
    #[test]
    fn http_host_and_split() {
        let head =
            b"GET / HTTP/1.1\r\nHost: example.com:8443\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(
            engine::host_from_http_head(&head[..head.len() - 4]),
            Some("example.com:8443".into())
        );
        assert_eq!(
            engine::split_host_port("example.com:8443", 80),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            engine::split_host_port("example.com", 80),
            ("example.com".into(), 80)
        );
        assert_eq!(
            engine::split_host_port("[::1]:9090", 80),
            ("::1".into(), 9090)
        );
    }
}
