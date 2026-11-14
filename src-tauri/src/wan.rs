//! Facts for the 外网 segment: hop loss and latency, ASN, NAT, and HTTPS.
//!
//! The playbook is text a person can read. Nothing in it is executed.
//! The app does not change DNS, proxy settings, routes, trust stores, or power.

use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const HTTPS_SAMPLE: &str = "www.baidu.com";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WanHop {
    pub ttl: u8,
    pub ip: String,
    pub ms: i64,
    pub loss: u8,
    pub kind: String,
    pub asn: String,
    pub asn_name: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHop {
    pub ttl: u8,
    pub ip: String,
    pub ms: i64,
    pub loss: u8,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WanCard {
    pub hops: Vec<WanHop>,
    pub nat: String,
    pub https: String,
    pub https_kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Playbook {
    pub id: String,
    pub look_at: Vec<String>,
    pub check_first: String,
    pub never_auto: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advice {
    pub playbook: Option<Playbook>,
    pub conclusion: Option<String>,
    pub next: Option<String>,
    pub highlight: bool,
}

impl Advice {
    fn quiet() -> Self {
        Self {
            playbook: None,
            conclusion: None,
            next: None,
            highlight: false,
        }
    }
}

struct Book {
    id: &'static str,
    look_at: &'static [&'static str],
    check_first: &'static str,
    never_auto: &'static [&'static str],
}

const BOOKS: &[Book] = &[
    Book {
        id: "wan-down",
        look_at: &["外网每一跳", "证书那一行是不是「连不上」"],
        check_first:
            "前面都过了。先看从第几跳开始无回应。写成连不上时，不是证书问题，再考虑重启光猫。",
        never_auto: &["不要自动重启光猫", "不要自动改 DNS", "不要自动关掉系统代理"],
    },
    Book {
        id: "wan-loss",
        look_at: &["哪一跳标了丢包", "这一跳的 ASN", "NAT 那一行"],
        check_first: "外网有丢包。先看从哪一跳开始丢，不要先重启这台电脑。",
        never_auto: &["不要自动换出口", "不要自动重启光猫", "不要自动改路由"],
    },
    Book {
        id: "wan-slow",
        look_at: &["最慢的那一跳", "它的 ASN"],
        check_first: "外网本身慢。先看最慢的那一跳，过几分钟再测。",
        never_auto: &["不要自动重启光猫", "不要自动改 DNS", "不要自动关掉系统代理"],
    },
    Book {
        id: "wan-cert",
        look_at: &["外网是通还是断", "证书那一句"],
        check_first: "连得上，证书不合格。先对一下电脑时间，不要继续打开，也不要信任这张证书。",
        never_auto: &[
            "不要自动信任证书",
            "不要自动安装根证书",
            "不要自动忽略证书警告",
        ],
    },
    Book {
        id: "wan-site",
        look_at: &["外网这一段的通断", "网址那一行是连不上，还是没有解析"],
        check_first: "外网地址有回应，这个网址没有连上。先核对网址，不要把它当成证书问题。",
        never_auto: &["不要自动改 hosts", "不要自动改 DNS", "不要自动信任证书"],
    },
    Book {
        id: "wan-tls",
        look_at: &["外网是通还是断", "这一句是加密握手没完成"],
        check_first: "地址连上了，加密握手没完成。这不是证书不合格。",
        never_auto: &[
            "不要自动信任证书",
            "不要自动忽略证书警告",
            "不要自动改系统时间",
        ],
    },
];

pub fn playbook(id: &str) -> Playbook {
    let book = BOOKS.iter().find(|b| b.id == id).unwrap_or(&BOOKS[0]);
    Playbook {
        id: book.id.to_string(),
        look_at: book.look_at.iter().map(|s| (*s).to_string()).collect(),
        check_first: book.check_first.to_string(),
        never_auto: book.never_auto.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn with_book(id: &str, conclusion: Option<&str>, highlight: bool) -> Advice {
    let book = playbook(id);
    Advice {
        next: Some(book.check_first.clone()),
        conclusion: conclusion.map(str::to_string),
        highlight,
        playbook: Some(book),
    }
}

/// Pick the sentence under the card. Certificate advice is used only when the
/// path itself is up; a dead path stays a connectivity result.
pub fn advise(mark: &str, https_kind: &str, dest_loss: f64) -> Advice {
    let path_up = mark != "断";
    if path_up && https_kind == "cert" {
        let conclusion = if mark == "慢" {
            "外网偏慢。打不开是证书问题。"
        } else {
            "外网是通的。打不开是证书问题。"
        };
        return with_book("wan-cert", Some(conclusion), true);
    }
    if path_up && https_kind == "down" {
        let conclusion = if mark == "慢" {
            "外网偏慢。这个网址连不上。"
        } else {
            "外网是通的。这个网址连不上。"
        };
        return with_book("wan-site", Some(conclusion), true);
    }
    if path_up && https_kind == "tls" {
        let conclusion = if mark == "慢" {
            "外网偏慢。加密握手没完成。"
        } else {
            "外网是通的。加密握手没完成。"
        };
        return with_book("wan-tls", Some(conclusion), true);
    }
    if mark == "断" {
        return with_book("wan-down", None, false);
    }
    if mark == "慢" {
        let id = if dest_loss > 0.0 && dest_loss < 100.0 {
            "wan-loss"
        } else {
            "wan-slow"
        };
        return with_book(id, None, false);
    }
    Advice::quiet()
}

pub fn summarize(
    target: &str,
    direct_ok: bool,
    via_ok: bool,
    hops: &[WanHop],
    dest_loss: f64,
) -> String {
    if !direct_ok && via_ok {
        if let Some(hop) = hops.iter().find(|h| h.kind == "down") {
            return format!("经代理出去 · 直连在第 {} 跳中断", hop.ttl);
        }
        return "经代理出去".to_string();
    }
    if !direct_ok {
        if let Some(hop) = hops.iter().find(|h| h.kind == "down") {
            return format!("到第 {} 跳中断", hop.ttl);
        }
        return "223.5.5.5 和 1.1.1.1 都没有回应".to_string();
    }
    let target = if target.is_empty() {
        "外网地址"
    } else {
        target
    };
    let mut parts = vec![target.to_string()];
    if hops.is_empty() {
        parts.push("跳数没有读到".to_string());
    } else {
        parts.push(format!("{} 跳", hops.len()));
    }
    if dest_loss >= 100.0 {
        parts.push("ping 没有回应".to_string());
    } else if dest_loss >= 0.0 {
        parts.push(format!("终点丢包 {dest_loss:.0}%"));
    }
    if let Some(asn) = summary_asn(hops) {
        parts.push(asn);
    }
    parts.join(" · ")
}

fn summary_asn(hops: &[WanHop]) -> Option<String> {
    let hop = hops
        .iter()
        .find(|h| !h.asn.is_empty() && ip_kind(&h.ip) == IpKind::Public)?;
    if hop.asn_name.is_empty() {
        Some(hop.asn.clone())
    } else {
        Some(format!("{} {}", hop.asn, hop.asn_name))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpKind {
    Public,
    Private,
    Cgnat,
    LinkLocal,
    Loopback,
    Other,
}

pub fn ip_kind(ip: &str) -> IpKind {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return IpKind::Other;
    };
    if addr.is_loopback() {
        return IpKind::Loopback;
    }
    if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
        return IpKind::Other;
    }
    let [a, b, _, _] = addr.octets();
    if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        IpKind::Private
    } else if a == 100 && (64..=127).contains(&b) {
        IpKind::Cgnat
    } else if a == 169 && b == 254 {
        IpKind::LinkLocal
    } else {
        IpKind::Public
    }
}

pub fn nat_fact(
    local: &str,
    mapped: &str,
    web: &str,
    symmetric: Option<bool>,
    hops: &[WanHop],
) -> String {
    let mapped = clean_ip(mapped);
    let web = clean_ip(web);
    let public = if !mapped.is_empty() { mapped } else { web };
    if public.is_empty() {
        if let Some(hop) = hops.iter().find(|h| ip_kind(&h.ip) == IpKind::Cgnat) {
            return format!("路径上有运营商地址 {}", hop.ip);
        }
        return String::new();
    }
    if local.is_empty() || ip_kind(local) == IpKind::Other {
        return format!("出口 {public}");
    }
    if local == public {
        return "没有地址转换".to_string();
    }
    let mut line = if ip_kind(local) == IpKind::Cgnat {
        format!("运营商 NAT {local} → {public}")
    } else {
        format!("NAT {local} → {public}")
    };
    if symmetric == Some(true) {
        line.push_str(" · 对称");
    }
    if ip_kind(local) != IpKind::Cgnat {
        if let Some(hop) = hops.iter().find(|h| ip_kind(&h.ip) == IpKind::Cgnat) {
            line.push_str(&format!(" · 中间还有 {}", hop.ip));
        }
    }
    if !mapped.is_empty() && !web.is_empty() && mapped != web {
        line.push_str(&format!(" · 网页出口 {web}"));
    }
    line
}

fn clean_ip(ip: &str) -> &str {
    match ip_kind(ip) {
        IpKind::Public | IpKind::Private | IpKind::Cgnat => ip,
        _ => "",
    }
}

/// Empty input uses the sample site. Anything that is not a hostname is refused.
pub fn resolve_site(raw: &str) -> Result<String, ()> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(HTTPS_SAMPLE.to_string());
    }
    site_host(raw).ok_or(())
}

pub fn site_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let raw = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or(raw);
    let raw = raw.split(['/', '?', '#']).next().unwrap_or("");
    let raw = raw.rsplit('@').next().unwrap_or("");
    if raw.is_empty() || raw.starts_with('[') {
        return None;
    }
    let host = if let Some((host, port)) = raw.rsplit_once(':') {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        host
    } else {
        raw
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('-')
        || host.starts_with('.')
        || host.ends_with('-')
        || host.contains("..")
    {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    Some(host)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRaw {
    pub ran: bool,
    pub verify: i32,
    pub connect_ms: i64,
    pub app_ms: i64,
    pub stderr: String,
}

impl HttpsRaw {
    pub fn not_run() -> Self {
        Self {
            ran: false,
            verify: 0,
            connect_ms: 0,
            app_ms: 0,
            stderr: String::new(),
        }
    }
}

/// Certificate wording requires a completed TCP connect.
/// Lookup failures and timeouts stay connectivity facts.
pub fn classify_https(host: &str, via_proxy: bool, raw: &HttpsRaw) -> (String, String) {
    if !raw.ran || host.is_empty() {
        return (String::new(), String::new());
    }
    let err = raw.stderr.to_ascii_lowercase();
    let head = if via_proxy {
        format!("{host} · 经代理")
    } else {
        host.to_string()
    };
    if err.contains("could not resolve") {
        return ("down".to_string(), format!("{head} · 没有解析"));
    }
    if raw.connect_ms <= 0 {
        return ("down".to_string(), format!("{head} · 连不上"));
    }
    if raw.verify != 0 || err.contains("certificate") || err.contains("subject name") {
        let why = cert_why(raw.verify, &err);
        return ("cert".to_string(), format!("{head} · {why} · 连得上"));
    }
    if raw.app_ms <= 0 {
        return (
            "tls".to_string(),
            format!("{head} · 加密握手没完成 · 连得上"),
        );
    }
    ("ok".to_string(), format!("{head} · 证书正常"))
}

fn cert_why(verify: i32, err: &str) -> &'static str {
    if verify == 10 || err.contains("expired") {
        "证书过期"
    } else if verify == 9 || err.contains("not yet valid") {
        "证书还没生效"
    } else if verify == 62
        || verify == 64
        || err.contains("subject name")
        || err.contains("does not match")
    {
        "证书域名不符"
    } else if verify == 23 || err.contains("revoked") {
        "证书已吊销"
    } else if verify == 19
        || verify == 20
        || verify == 21
        || verify == 27
        || err.contains("in certificate chain")
        || err.contains("unable to get local issuer")
        || err.contains("untrusted")
    {
        "证书不受信任"
    } else if verify == 18 || err.contains("self-signed") || err.contains("self signed") {
        "自签名证书"
    } else {
        "证书不合格"
    }
}

pub fn parse_curl_metrics(stdout: &str) -> (i32, i64, i64) {
    let mut verify = 0;
    let mut connect = 0.0;
    let mut app = 0.0;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("verify=") {
            verify = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("connect=") {
            connect = v.trim().parse().unwrap_or(0.0);
        } else if let Some(v) = line.strip_prefix("app=") {
            app = v.trim().parse().unwrap_or(0.0);
        }
    }
    (verify, seconds_to_ms(connect), seconds_to_ms(app))
}

fn seconds_to_ms(seconds: f64) -> i64 {
    if seconds <= 0.0 {
        0
    } else {
        round_ms(seconds * 1000.0)
    }
}

fn round_ms(ms: f64) -> i64 {
    if ms <= 0.0 {
        0
    } else {
        let n = ms.round() as i64;
        if n < 1 {
            1
        } else {
            n
        }
    }
}

pub fn https_args(host: &str, proxy: Option<&str>) -> Option<Vec<String>> {
    let host = site_host(host)?;
    let mut args = vec![
        "-sS".to_string(),
        "-4".to_string(),
        "-o".to_string(),
        "/dev/null".to_string(),
        "--connect-timeout".to_string(),
        "4".to_string(),
        "--max-time".to_string(),
        "8".to_string(),
        "--proto".to_string(),
        "=https".to_string(),
        "-w".to_string(),
        "verify=%{ssl_verify_result}\nconnect=%{time_connect}\napp=%{time_appconnect}\n"
            .to_string(),
    ];
    if let Some(proxy) = proxy {
        if proxy_ok(proxy) {
            args.push("-x".to_string());
            args.push(proxy.to_string());
        }
    }
    args.push("--url".to_string());
    args.push(format!("https://{host}/"));
    Some(args)
}

fn proxy_ok(proxy: &str) -> bool {
    !proxy.is_empty()
        && !proxy.starts_with('-')
        && !proxy.chars().any(|c| c.is_whitespace())
        && (proxy.starts_with("http://") || proxy.starts_with("socks5h://"))
}

pub fn https_probe(host: &str, proxy: Option<&str>) -> HttpsRaw {
    let Some(args) = https_args(host, proxy) else {
        return HttpsRaw::not_run();
    };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((stdout, stderr)) = run_bounded("curl", &refs, Duration::from_secs(10)) else {
        return HttpsRaw::not_run();
    };
    if stdout.trim().is_empty() && !stderr.to_ascii_lowercase().contains("curl:") {
        return HttpsRaw::not_run();
    }
    let (verify, connect_ms, app_ms) = parse_curl_metrics(&stdout);
    HttpsRaw {
        ran: true,
        verify,
        connect_ms,
        app_ms,
        stderr,
    }
}

pub fn parse_traceroute(text: &str) -> Vec<ProbeHop> {
    let mut hops = Vec::new();
    for line in text.lines() {
        if hops.len() >= 8 {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.contains("hops max") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let Ok(ttl) = parts[0].parse::<u8>() else {
            continue;
        };
        if ttl == 0 {
            continue;
        }
        let mut ip = String::new();
        let mut samples = Vec::new();
        let mut timeouts = 0u8;
        let mut i = 1;
        while i < parts.len() {
            let part = parts[i];
            if part == "*" {
                timeouts = timeouts.saturating_add(1);
                i += 1;
                continue;
            }
            if part.starts_with('!') {
                i += 1;
                continue;
            }
            let timed = if i + 1 < parts.len() && parts[i + 1].starts_with("ms") {
                part.parse::<f64>().ok().map(|ms| {
                    i += 2;
                    ms
                })
            } else if let Some(num) = part.strip_suffix("ms") {
                num.trim().parse::<f64>().ok().map(|ms| {
                    i += 1;
                    ms
                })
            } else {
                None
            };
            if let Some(ms) = timed {
                if ms >= 0.0 {
                    samples.push(ms);
                }
                continue;
            }
            if part.starts_with('(') && part.ends_with(')') && part.len() > 2 {
                let inner = &part[1..part.len() - 1];
                if inner.parse::<IpAddr>().is_ok() && ip.is_empty() {
                    ip = inner.to_string();
                }
                i += 1;
                continue;
            }
            if part.parse::<IpAddr>().is_ok() && ip.is_empty() {
                ip = part.to_string();
            }
            i += 1;
        }
        let sent = timeouts as usize + samples.len();
        if sent == 0 && ip.is_empty() {
            continue;
        }
        let loss = if sent == 0 {
            0
        } else {
            ((timeouts as usize * 100) / sent) as u8
        };
        let ms = if samples.is_empty() {
            0
        } else {
            round_ms(samples.iter().sum::<f64>() / samples.len() as f64)
        };
        hops.push(ProbeHop { ttl, ip, ms, loss });
    }
    hops
}

pub fn lay_out(probes: &[ProbeHop], reached: bool) -> Vec<WanHop> {
    let last_answer = probes.iter().rposition(|p| !p.ip.is_empty());
    let mut hops = Vec::new();
    for (index, probe) in probes.iter().enumerate() {
        if probe.ip.is_empty() {
            let later = last_answer.map(|n| index < n).unwrap_or(false);
            if later || reached {
                hops.push(blank_hop(probe.ttl, "silent"));
            } else if hops.last().is_some_and(|h: &WanHop| h.kind == "down") {
                continue;
            } else {
                hops.push(blank_hop(probe.ttl, "down"));
            }
            continue;
        }
        let kind = if probe.loss > 0 { "loss" } else { "ok" };
        hops.push(WanHop {
            ttl: probe.ttl,
            ip: probe.ip.clone(),
            ms: probe.ms,
            loss: probe.loss,
            kind: kind.to_string(),
            asn: String::new(),
            asn_name: String::new(),
            note: hop_note(kind, probe.loss, "", &probe.ip),
        });
    }
    if reached && hops.iter().all(|h| h.kind == "silent") {
        return Vec::new();
    }
    hops
}

fn blank_hop(ttl: u8, kind: &str) -> WanHop {
    WanHop {
        ttl,
        ip: String::new(),
        ms: 0,
        loss: 0,
        kind: kind.to_string(),
        asn: String::new(),
        asn_name: String::new(),
        note: hop_note(kind, 0, "", ""),
    }
}

pub fn hop_note(kind: &str, loss: u8, asn: &str, ip: &str) -> String {
    match kind {
        "silent" => "不回".to_string(),
        "down" => "中断".to_string(),
        "loss" => {
            if asn.is_empty() {
                format!("{loss}%")
            } else {
                format!("{loss}% · {asn}")
            }
        }
        _ => {
            if !asn.is_empty() {
                asn.to_string()
            } else {
                ip.to_string()
            }
        }
    }
}

pub fn finish_probes(probes: &[ProbeHop], reached: bool) -> Vec<WanHop> {
    finish_with(probes, reached, lookup_asn)
}

pub fn finish_with(
    probes: &[ProbeHop],
    reached: bool,
    lookup: fn(&str) -> (String, String),
) -> Vec<WanHop> {
    let mut hops = lay_out(probes, reached);
    if hops.is_empty() {
        return hops;
    }
    let mut uniq = Vec::new();
    for hop in &hops {
        if ip_kind(&hop.ip) == IpKind::Public && !uniq.contains(&hop.ip) {
            uniq.push(hop.ip.clone());
        }
    }
    let found: Vec<(String, (String, String))> = if uniq.is_empty() {
        Vec::new()
    } else {
        thread::scope(|scope| {
            let handles: Vec<_> = uniq
                .iter()
                .map(|ip| {
                    scope.spawn(|| {
                        let pair = lookup(ip);
                        (ip.clone(), pair)
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .collect()
        })
    };
    for hop in &mut hops {
        if let Some((_, (asn, name))) = found.iter().find(|(ip, _)| ip == &hop.ip) {
            hop.asn = asn.clone();
            hop.asn_name = name.clone();
        }
        hop.note = hop_note(&hop.kind, hop.loss, &hop.asn, &hop.ip);
    }
    hops
}

pub fn trace_path(target: &str) -> Vec<ProbeHop> {
    if target.parse::<Ipv4Addr>().is_err() {
        return Vec::new();
    }
    let args = ["-n", "-q", "2", "-w", "1", "-m", "6", target];
    let out = run_bounded("traceroute", &args, Duration::from_secs(14))
        .or_else(|| run_bounded("/usr/sbin/traceroute", &args, Duration::from_secs(14)));
    match out {
        Some((stdout, _)) => parse_traceroute(&stdout),
        None => Vec::new(),
    }
}

pub fn parse_asn_txt(text: &str) -> String {
    for line in text.lines() {
        let line = line.trim().trim_matches('"').trim();
        if line.is_empty() {
            continue;
        }
        let first = line.split('|').next().unwrap_or("").trim();
        let token = first.trim_start_matches("AS").trim_start_matches("as");
        if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
            return format!("AS{token}");
        }
    }
    String::new()
}

pub fn parse_asn_name(text: &str) -> String {
    for line in text.lines() {
        let line = line.trim().trim_matches('"').trim();
        let mut parts = line.split('|');
        let Some(name) = parts.nth(4) else {
            continue;
        };
        let name = short_org(name);
        if !name.is_empty() {
            return name;
        }
    }
    String::new()
}

fn short_org(name: &str) -> String {
    let name = name.trim();
    let name = name.split(" - ").next().unwrap_or(name).trim();
    let name = name.split(',').next().unwrap_or(name).trim();
    name.chars().take(24).collect()
}

fn origin_query(ip: &str) -> Option<String> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    let o = addr.octets();
    Some(format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        o[3], o[2], o[1], o[0]
    ))
}

fn asn_cache() -> &'static Mutex<HashMap<String, (String, String)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, String)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn lookup_asn(ip: &str) -> (String, String) {
    if ip_kind(ip) != IpKind::Public {
        return (String::new(), String::new());
    }
    {
        let guard = asn_cache().lock().unwrap_or_else(|err| err.into_inner());
        if let Some(hit) = guard.get(ip) {
            return hit.clone();
        }
    }
    let Some(query) = origin_query(ip) else {
        return (String::new(), String::new());
    };
    let Some((stdout, _)) = run_bounded(
        "dig",
        &["+short", "+time=1", "+tries=1", "TXT", &query],
        Duration::from_secs(3),
    ) else {
        return (String::new(), String::new());
    };
    let asn = parse_asn_txt(&stdout);
    if asn.is_empty() {
        return (String::new(), String::new());
    }
    let name_query = format!("{asn}.asn.cymru.com");
    let name = run_bounded(
        "dig",
        &["+short", "+time=1", "+tries=1", "TXT", &name_query],
        Duration::from_secs(3),
    )
    .map(|(text, _)| parse_asn_name(&text))
    .unwrap_or_default();
    let mut guard = asn_cache().lock().unwrap_or_else(|err| err.into_inner());
    guard.insert(ip.to_string(), (asn.clone(), name.clone()));
    (asn, name)
}

pub fn web_egress() -> String {
    let Some((stdout, _)) = run_bounded(
        "curl",
        &[
            "-4",
            "-s",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            "--proto",
            "=https",
            "--url",
            "https://1.1.1.1/cdn-cgi/trace",
        ],
        Duration::from_secs(6),
    ) else {
        return String::new();
    };
    for line in stdout.lines() {
        if let Some(ip) = line.trim().strip_prefix("ip=") {
            if matches!(
                ip_kind(ip),
                IpKind::Public | IpKind::Private | IpKind::Cgnat
            ) {
                return ip.to_string();
            }
        }
    }
    String::new()
}

static STUN_BUSY: AtomicBool = AtomicBool::new(false);

pub fn stun_map() -> (String, Option<bool>) {
    let servers = stun_servers();
    if servers.is_empty() {
        return (String::new(), None);
    }
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return (String::new(), None);
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(800)));
    let mut tids = Vec::new();
    for (index, server) in servers.iter().take(2).enumerate() {
        let tid = new_tid(index as u8);
        if sock.send_to(&binding_request(&tid), server).is_ok() {
            tids.push(tid);
        }
    }
    if tids.is_empty() {
        return (String::new(), None);
    }
    let mut found = Vec::new();
    let mut buf = [0u8; 576];
    for _ in 0..4 {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                for tid in &tids {
                    if let Some(pair) = parse_stun_mapped(&buf[..n], tid) {
                        if !found.contains(&pair) {
                            found.push(pair);
                        }
                    }
                }
                if found.len() >= tids.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if found.is_empty() {
        return (String::new(), None);
    }
    let symmetric = if found.len() >= 2 {
        Some(found[0] != found[1])
    } else {
        None
    };
    (found[0].0.clone(), symmetric)
}

fn stun_servers() -> Vec<SocketAddr> {
    if STUN_BUSY
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Vec::new();
    }
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut found = Vec::new();
        for (host, port) in [
            ("stun.cloudflare.com", 3478u16),
            ("stun.l.google.com", 19302u16),
        ] {
            if let Ok(mut addrs) = (host, port).to_socket_addrs() {
                if let Some(addr) = addrs.find(|addr| addr.is_ipv4()) {
                    found.push(addr);
                }
            }
        }
        let _ = tx.send(found);
        STUN_BUSY.store(false, Ordering::SeqCst);
    });
    rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default()
}

fn new_tid(mark: u8) -> [u8; 12] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let mut tid = [0u8; 12];
    tid[0] = mark;
    tid[1..9].copy_from_slice(&nanos.to_le_bytes()[..8]);
    tid
}

fn binding_request(tid: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[1] = 0x01;
    msg[4] = 0x21;
    msg[5] = 0x12;
    msg[6] = 0xA4;
    msg[7] = 0x42;
    msg[8..20].copy_from_slice(tid);
    msg
}

pub fn parse_stun_mapped(buf: &[u8], tid: &[u8; 12]) -> Option<(String, u16)> {
    if buf.len() < 20 {
        return None;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    if kind != 0x0101 {
        return None;
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 20 + length {
        return None;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != 0x2112_A442 || &buf[8..20] != tid {
        return None;
    }
    let mut index = 20;
    let end = 20 + length;
    while index + 4 <= end {
        let attr = u16::from_be_bytes([buf[index], buf[index + 1]]);
        let alen = u16::from_be_bytes([buf[index + 2], buf[index + 3]]) as usize;
        let value_at = index + 4;
        if value_at + alen > end {
            break;
        }
        if attr == 0x0020 || attr == 0x0001 {
            if let Some(pair) = decode_address(&buf[value_at..value_at + alen], attr == 0x0020) {
                return Some(pair);
            }
        }
        let padded = (alen + 3) & !3;
        index = value_at + padded;
    }
    None
}

fn decode_address(value: &[u8], xor: bool) -> Option<(String, u16)> {
    if value.len() < 8 || value[1] != 0x01 {
        return None;
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let mut addr = [value[4], value[5], value[6], value[7]];
    if xor {
        port ^= 0x2112;
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        for (byte, mask) in addr.iter_mut().zip(cookie) {
            *byte ^= mask;
        }
    }
    Some((Ipv4Addr::from(addr).to_string(), port))
}

fn run_bounded(cmd: &str, args: &[&str], timeout: Duration) -> Option<(String, String)> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(30)),
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    Some((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_asn(_ip: &str) -> (String, String) {
        (String::new(), String::new())
    }

    fn fake_asn(ip: &str) -> (String, String) {
        if ip == "203.0.113.9" {
            ("AS4134".to_string(), "CHINANET-BACKBONE".to_string())
        } else {
            (String::new(), String::new())
        }
    }

    #[test]
    fn traceroute_keeps_loss_separate_from_a_silent_hop() {
        let sample = "\
traceroute to 1.1.1.1 (1.1.1.1), 6 hops max, 52 byte packets
 1  192.168.1.1  2.345 ms  1.902 ms
 2  * *
 3  100.64.0.1  12.440 ms *
 4  host.example (203.0.113.9)  21.000 ms  19.000 ms
 5  1.1.1.1  28.500 ms !H  27.500 ms
";
        let probes = parse_traceroute(sample);
        assert_eq!(probes.len(), 5);
        assert_eq!(probes[0].ip, "192.168.1.1");
        assert_eq!(probes[0].loss, 0);
        assert_eq!(probes[0].ms, 2);
        assert_eq!(probes[1].ip, "");
        assert_eq!(probes[1].loss, 100);
        assert_eq!(probes[2].loss, 50);
        assert_eq!(probes[2].ms, 12);
        assert_eq!(probes[3].ip, "203.0.113.9");
        assert_eq!(probes[3].ms, 20);
        assert_eq!(probes[4].ip, "1.1.1.1");
        assert_eq!(probes[4].loss, 0);
        assert_eq!(probes[4].ms, 28);

        let laid = finish_with(&probes, true, fake_asn);
        assert_eq!(laid[1].kind, "silent");
        assert_eq!(laid[1].note, "不回");
        assert_eq!(laid[2].kind, "loss");
        assert_eq!(laid[2].note, "50%");
        assert_eq!(laid[3].asn, "AS4134");
        assert_eq!(laid[3].note, "AS4134");
        assert!(laid.iter().all(|h| h.kind != "down"));
    }

    #[test]
    fn a_star_after_the_last_answer_is_a_break_only_when_the_target_was_not_reached() {
        let sample = "\
 1  192.168.1.1  1.0 ms  1.2 ms
 2  * *
 3  * *
";
        let probes = parse_traceroute(sample);
        let broken = lay_out(&probes, false);
        assert_eq!(broken.len(), 2);
        assert_eq!(broken[1].kind, "down");
        assert_eq!(broken[1].note, "中断");
        let reached = lay_out(&probes, true);
        assert!(reached.iter().all(|h| h.kind != "down"));
    }

    #[test]
    fn traceroute_that_never_answers_does_not_invent_loss_when_tcp_worked() {
        let sample = " 1  * *\n 2  * *\n";
        let probes = parse_traceroute(sample);
        assert!(finish_with(&probes, true, no_asn).is_empty());
        let down = finish_with(&probes, false, no_asn);
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].kind, "down");
    }

    #[test]
    fn asn_text_uses_the_first_number_and_the_org() {
        assert_eq!(
            parse_asn_txt("\"4134 | 202.97.0.0/16 | CN | apnic | 2002-01-01\"\n"),
            "AS4134"
        );
        assert_eq!(
            parse_asn_name(
                "\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US\"\n"
            ),
            "CLOUDFLARENET"
        );
        assert_eq!(parse_asn_txt("nope"), "");
    }

    #[test]
    fn nat_line_names_translation_without_guessing_a_type() {
        let cgnat = WanHop {
            ttl: 2,
            ip: "100.64.0.1".into(),
            ms: 8,
            loss: 0,
            kind: "ok".into(),
            asn: String::new(),
            asn_name: String::new(),
            note: "100.64.0.1".into(),
        };
        assert_eq!(
            nat_fact("192.168.1.20", "203.0.113.8", "203.0.113.8", None, &[]),
            "NAT 192.168.1.20 → 203.0.113.8"
        );
        assert_eq!(
            nat_fact(
                "192.168.1.20",
                "203.0.113.8",
                "203.0.113.8",
                Some(true),
                &[]
            ),
            "NAT 192.168.1.20 → 203.0.113.8 · 对称"
        );
        assert_eq!(
            nat_fact("203.0.113.8", "203.0.113.8", "", None, &[]),
            "没有地址转换"
        );
        assert_eq!(
            nat_fact("100.64.1.2", "203.0.113.8", "", None, &[]),
            "运营商 NAT 100.64.1.2 → 203.0.113.8"
        );
        assert!(
            nat_fact("192.168.1.20", "203.0.113.8", "", None, &[cgnat.clone()])
                .contains("中间还有 100.64.0.1")
        );
        assert_eq!(
            nat_fact("", "", "", None, &[cgnat]),
            "路径上有运营商地址 100.64.0.1"
        );
        assert_eq!(nat_fact("", "", "", None, &[]), "");
        assert!(nat_fact(
            "192.168.1.20",
            "203.0.113.8",
            "198.51.100.9",
            Some(false),
            &[]
        )
        .contains("网页出口 198.51.100.9"));
        assert!(!nat_fact(
            "192.168.1.20",
            "203.0.113.8",
            "198.51.100.9",
            Some(false),
            &[]
        )
        .contains("对称"));
    }

    #[test]
    fn certificate_needs_a_tcp_connect() {
        let expired = HttpsRaw {
            ran: true,
            verify: 10,
            connect_ms: 30,
            app_ms: 0,
            stderr: "curl: (60) SSL certificate problem: certificate has expired".into(),
        };
        let (kind, line) = classify_https("shop.example", false, &expired);
        assert_eq!(kind, "cert");
        assert_eq!(line, "shop.example · 证书过期 · 连得上");

        let timed_out = HttpsRaw {
            ran: true,
            verify: 10,
            connect_ms: 0,
            app_ms: 0,
            stderr: "curl: (28) Timeout was reached".into(),
        };
        let (kind, line) = classify_https("shop.example", false, &timed_out);
        assert_eq!(kind, "down");
        assert_eq!(line, "shop.example · 连不上");
        assert!(!line.contains("证书"));

        let unresolved = HttpsRaw {
            ran: true,
            verify: 0,
            connect_ms: 0,
            app_ms: 0,
            stderr: "curl: (6) Could not resolve host: shop.example".into(),
        };
        assert_eq!(
            classify_https("shop.example", false, &unresolved).1,
            "shop.example · 没有解析"
        );

        let mismatch = HttpsRaw {
            ran: true,
            verify: 1,
            connect_ms: 27,
            app_ms: 0,
            stderr: "SSL: no alternative certificate subject name matches target host name".into(),
        };
        assert_eq!(
            classify_https("wrong.host.example", false, &mismatch).1,
            "wrong.host.example · 证书域名不符 · 连得上"
        );

        let trusted = HttpsRaw {
            ran: true,
            verify: 0,
            connect_ms: 4,
            app_ms: 20,
            stderr: String::new(),
        };
        let (kind, line) = classify_https("www.baidu.com", true, &trusted);
        assert_eq!(kind, "ok");
        assert_eq!(line, "www.baidu.com · 经代理 · 证书正常");

        let handshake = HttpsRaw {
            ran: true,
            verify: 0,
            connect_ms: 15,
            app_ms: 0,
            stderr: "curl: (35) TLS connect error".into(),
        };
        assert_eq!(classify_https("a.example", false, &handshake).0, "tls");
    }

    #[test]
    fn https_probe_does_not_skip_verification() {
        let args = https_args("Example.COM", Some("http://127.0.0.1:8080")).unwrap();
        assert!(!args.iter().any(|arg| arg == "-k" || arg == "--insecure"));
        assert!(args.iter().any(|arg| arg == "https://example.com/"));
        assert!(args.iter().any(|arg| arg == "http://127.0.0.1:8080"));
        assert!(https_args("-k", None).is_none());
        assert!(https_args("bad host", None).is_none());
    }

    #[test]
    fn site_host_strips_a_url_and_refuses_flags() {
        assert_eq!(
            site_host("https://User:pw@Example.COM:443/a?b").as_deref(),
            Some("example.com")
        );
        assert_eq!(resolve_site("").unwrap(), HTTPS_SAMPLE);
        assert!(resolve_site("不是网址").is_err());
        assert!(site_host("--insecure").is_none());
        assert!(site_host("").is_none());
    }

    #[test]
    fn summary_names_hops_loss_and_asn_without_replacing_a_proxy_exit() {
        let hops = vec![
            WanHop {
                ttl: 1,
                ip: "192.168.1.1".into(),
                ms: 2,
                loss: 0,
                kind: "ok".into(),
                asn: String::new(),
                asn_name: String::new(),
                note: "192.168.1.1".into(),
            },
            WanHop {
                ttl: 4,
                ip: "203.0.113.9".into(),
                ms: 21,
                loss: 0,
                kind: "ok".into(),
                asn: "AS4134".into(),
                asn_name: "CHINANET-BACKBONE".into(),
                note: "AS4134".into(),
            },
        ];
        let line = summarize("1.1.1.1", true, false, &hops, 0.0);
        assert_eq!(
            line,
            "1.1.1.1 · 2 跳 · 终点丢包 0% · AS4134 CHINANET-BACKBONE"
        );
        let mut broken = hops.clone();
        broken.push(WanHop {
            ttl: 5,
            ip: String::new(),
            ms: 0,
            loss: 0,
            kind: "down".into(),
            asn: String::new(),
            asn_name: String::new(),
            note: "中断".into(),
        });
        assert_eq!(
            summarize("1.1.1.1", false, true, &broken, 100.0),
            "经代理出去 · 直连在第 5 跳中断"
        );
        assert_eq!(
            summarize("", false, false, &[], -1.0),
            "223.5.5.5 和 1.1.1.1 都没有回应"
        );
    }

    #[test]
    fn advice_keeps_a_certificate_apart_from_a_dead_path() {
        let dead = advise("断", "down", -1.0);
        assert!(!dead.highlight);
        assert!(dead.conclusion.is_none());
        assert!(dead.next.unwrap().contains("不是证书问题"));
        assert!(dead
            .playbook
            .unwrap()
            .never_auto
            .iter()
            .any(|line| line.contains("不要自动重启光猫")));

        let cert = advise("通", "cert", 0.0);
        assert!(cert.highlight);
        assert_eq!(
            cert.conclusion.as_deref(),
            Some("外网是通的。打不开是证书问题。")
        );
        let book = cert.playbook.unwrap();
        assert_eq!(book.id, "wan-cert");
        assert!(book.never_auto.iter().any(|line| line.contains("信任")));
        assert!(!book.check_first.contains("重启光猫"));

        let site = advise("通", "down", -1.0);
        assert_eq!(
            site.conclusion.as_deref(),
            Some("外网是通的。这个网址连不上。")
        );
        assert!(!site.conclusion.unwrap().contains("证书问题"));

        let loss = advise("慢", "ok", 33.0);
        assert_eq!(loss.playbook.unwrap().id, "wan-loss");
        assert!(!loss.highlight);

        let slow = advise("慢", "", -1.0);
        assert_eq!(slow.playbook.unwrap().id, "wan-slow");

        assert!(advise("通", "ok", 0.0).playbook.is_none());
    }

    #[test]
    fn every_playbook_names_what_to_read_and_what_stays_manual() {
        for id in [
            "wan-down", "wan-loss", "wan-slow", "wan-cert", "wan-site", "wan-tls",
        ] {
            let book = playbook(id);
            assert_eq!(book.id, id);
            assert!(!book.look_at.is_empty());
            assert!(!book.check_first.is_empty());
            assert!(book.never_auto.len() >= 2);
            assert!(book
                .never_auto
                .iter()
                .all(|line| line.starts_with("不要自动")));
        }
    }

    #[test]
    fn stun_mapped_address_is_decoded() {
        let tid = [9u8; 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x01, 0x01, 0x00, 0x0c]);
        msg.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        msg.extend_from_slice(&tid);
        msg.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
        let port = 4567u16 ^ 0x2112;
        let ip = Ipv4Addr::new(203, 0, 113, 8).octets();
        let cookie = [0x21u8, 0x12, 0xA4, 0x42];
        msg.push(0);
        msg.push(0x01);
        msg.extend_from_slice(&port.to_be_bytes());
        for (byte, mask) in ip.iter().zip(cookie) {
            msg.push(byte ^ mask);
        }
        assert_eq!(
            parse_stun_mapped(&msg, &tid),
            Some(("203.0.113.8".to_string(), 4567))
        );
        assert_eq!(parse_stun_mapped(&msg, &[1u8; 12]), None);
    }

    #[test]
    fn curl_metrics_read_seconds() {
        let text = "verify=10\nconnect=0.030166\napp=0.000000\n";
        assert_eq!(parse_curl_metrics(text), (10, 30, 0));
    }

    #[test]
    #[ignore]
    fn live_certificate_words_match_curl() {
        let expired = https_probe("expired.badssl.com", None);
        let (kind, line) = classify_https("expired.badssl.com", false, &expired);
        eprintln!(
            "expired {kind} {line} verify={} connect={}",
            expired.verify, expired.connect_ms
        );
        assert_eq!(kind, "cert");
        assert!(line.contains("证书过期"));
        assert!(line.contains("连得上"));

        let missing = https_probe("no-such-host.lanwatch.invalid", None);
        let (kind, line) = classify_https("no-such-host.lanwatch.invalid", false, &missing);
        eprintln!("missing {kind} {line}");
        assert_eq!(kind, "down");
        assert!(line.contains("没有解析"));
        assert!(!line.contains("证书"));

        let ok = https_probe("example.com", None);
        let (kind, line) = classify_https("example.com", false, &ok);
        eprintln!("ok {kind} {line}");
        assert_eq!(kind, "ok");

        let egress = web_egress();
        let (mapped, symmetric) = stun_map();
        eprintln!("egress {egress} mapped {mapped} symmetric {symmetric:?}");
        assert!(!egress.is_empty() || !mapped.is_empty());
    }

    #[test]
    fn bounded_command_reads_stdout_and_stops() {
        let (out, _) = run_bounded("echo", &["lanwatch"], Duration::from_secs(2)).unwrap();
        assert_eq!(out.trim(), "lanwatch");
        let start = Instant::now();
        let _ = run_bounded("sleep", &["30"], Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
