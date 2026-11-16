#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod wan;

use serde::Serialize;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ALI_DNS: &str = "223.5.5.5";
const CF_DNS: &str = "1.1.1.1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Up,
    Slow,
    Down,
}

impl Mark {
    fn as_str(self) -> &'static str {
        match self {
            Mark::Up => "通",
            Mark::Slow => "慢",
            Mark::Down => "断",
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct Hop {
    id: String,
    name: String,
    mark: String,
    number: i64,
    unit: String,
    detail: String,
}

#[derive(Debug, Serialize, Clone)]
struct Chain {
    hops: Vec<Hop>,
    conclusion: String,
    next: String,
    problem_id: String,
    wan: wan::WanCard,
    playbook: Option<wan::Playbook>,
}

struct Readings {
    loop_ok: bool,
    loop_ms: i64,
    nic_up: bool,
    nic_wifi: bool,
    rssi: i32,
    rssi_valid: bool,
    mbps: i64,
    has_gw: bool,
    gw_replied: bool,
    gw_ms: i64,
    gw_loss: f64,
    has_dns: bool,
    dns_ok: bool,
    dns_ms: i64,
    proxy_on: bool,
    proxy_accepting: bool,
    proxy_connect_ms: i64,
    via_tested: bool,
    via_ok: bool,
    via_ms: i64,
    direct_ok: bool,
    direct_ms: i64,
    computer_name: String,
    nic_ip: String,
    nic_label: String,
    gateway: String,
    dns_server: String,
    proxy_address: String,
    wan_target: String,
    link_local: bool,
    noise: i32,
    noise_valid: bool,
    tx_mbps: i64,
    self_conflict: bool,
    gw_conflict: bool,
    gw_mac_changed: bool,
    tx_bps: i64,
    rx_bps: i64,
    wan_hops: Vec<wan::WanHop>,
    wan_traced: bool,
    dest_loss: f64,
    nat_line: String,
    https_kind: String,
    https_line: String,
    band: String,
    channel: u32,
    local_proxy_port: u16,
    clash_mode: String,
    redirect_count: u32,
    redirect_portal: bool,
}

fn hop(id: &str, name: &str, mark: Mark, number: i64, unit: &str, detail: &str) -> Hop {
    Hop {
        id: id.to_string(),
        name: name.to_string(),
        mark: mark.as_str().to_string(),
        number,
        unit: unit.to_string(),
        detail: detail.to_string(),
    }
}

fn shown_ms(avg: f64) -> i64 {
    let n = avg.round() as i64;
    if n < 1 {
        1
    } else {
        n
    }
}

/// First break wins. If nothing is broken, the first slow segment is the one to name.
fn judge(r: &Readings) -> Chain {
    let computer_line = computer_detail(r);
    let computer = if !r.loop_ok {
        hop("computer", "这台电脑", Mark::Down, 0, "ms", &computer_line)
    } else if r.loop_ms > 10 {
        hop(
            "computer",
            "这台电脑",
            Mark::Slow,
            r.loop_ms,
            "ms",
            &computer_line,
        )
    } else {
        hop(
            "computer",
            "这台电脑",
            Mark::Up,
            r.loop_ms,
            "ms",
            &computer_line,
        )
    };

    let nic = judge_nic(r);
    let mut router = judge_router(r);
    let dns = judge_dns(r);
    let proxy = judge_proxy(r);
    let wan = judge_wan(r);
    let mut computer = computer;

    if r.self_conflict {
        computer = hop(
            "computer",
            "这台电脑",
            Mark::Down,
            0,
            "ms",
            "本机地址有两块网卡",
        );
    }
    if r.gw_conflict {
        let line = if r.gateway.is_empty() {
            "网关地址有两块网卡".to_string()
        } else {
            format!("{} 有两块网卡", r.gateway)
        };
        router = hop("router", "路由器", Mark::Down, 0, "ms", &line);
    } else if r.gw_mac_changed && router.mark != "断" {
        let line = format!("{} · 硬件地址变了", router.detail);
        router = hop("router", "路由器", Mark::Slow, router.number, "ms", &line);
    }
    let busy = r.tx_bps.max(r.rx_bps) >= 1_000_000;
    if busy && computer.mark == "通" && (router.mark == "慢" || wan.mark == "慢") {
        computer.mark = "慢".to_string();
    }

    let hops = vec![computer, nic, router, dns, proxy, wan.clone()];
    let redirect = wan::RedirectFact {
        count: r.redirect_count,
        portal: r.redirect_portal,
    };
    let advice = wan::advise(&wan.mark, &r.https_kind, r.dest_loss, redirect);

    let problem = hops
        .iter()
        .find(|h| h.mark == "断")
        .or_else(|| hops.iter().find(|h| h.mark == "慢"));
    let (conclusion, next, problem_id, playbook) = match problem {
        Some(h) if h.id != "wan" => {
            let book = segment_book(h);
            let next = book
                .as_ref()
                .map(|item| item.check_first.clone())
                .unwrap_or_else(|| next_for(h));
            (conclusion_for(h), next, h.id.clone(), book)
        }
        Some(_) => {
            let conclusion = advice
                .conclusion
                .clone()
                .unwrap_or_else(|| conclusion_for(&wan));
            let next = advice.next.clone().unwrap_or_else(|| next_for(&wan));
            (conclusion, next, "wan".to_string(), advice.playbook)
        }
        None if advice.highlight => {
            let conclusion = advice
                .conclusion
                .clone()
                .unwrap_or_else(|| "外网是通的。".to_string());
            let next = advice
                .next
                .clone()
                .unwrap_or_else(|| "不用做什么。".to_string());
            (conclusion, next, "wan".to_string(), advice.playbook)
        }
        None => (
            "从这台电脑到外网是通的。".to_string(),
            "不用做什么。".to_string(),
            String::new(),
            None,
        ),
    };

    Chain {
        hops,
        conclusion,
        next,
        problem_id,
        wan: wan::WanCard {
            hops: r.wan_hops.clone(),
            nat: r.nat_line.clone(),
            https: wan::https_with_redirect(&r.https_line, redirect),
            https_kind: r.https_kind.clone(),
            path: if r.proxy_on && r.wan_traced {
                "直连".to_string()
            } else {
                String::new()
            },
        },
        playbook,
    }
}

fn judge_nic(r: &Readings) -> Hop {
    let detail = nic_detail(r);
    if !r.nic_up {
        return hop("nic", "网卡", Mark::Down, 0, "", &detail);
    }
    if r.nic_wifi && r.rssi_valid && r.rssi < 0 {
        let mut mark = if r.rssi <= -75 { Mark::Slow } else { Mark::Up };
        if mark == Mark::Up && air_poor(r) {
            mark = Mark::Slow;
        }
        return hop("nic", "网卡", mark, r.rssi as i64, "dBm", &detail);
    }
    if r.nic_wifi && air_poor(r) {
        return hop("nic", "网卡", Mark::Slow, r.tx_mbps, "", &detail);
    }
    if !r.nic_wifi && r.mbps > 0 {
        let mark = if r.mbps < 100 { Mark::Slow } else { Mark::Up };
        return hop("nic", "网卡", mark, r.mbps, "Mbps", &detail);
    }
    hop("nic", "网卡", Mark::Up, 0, "", &detail)
}

fn judge_router(r: &Readings) -> Hop {
    let detail = router_detail(r);
    let replied = r.has_gw && r.gw_replied && r.gw_loss < 50.0;
    if !replied {
        return hop("router", "路由器", Mark::Down, 0, "ms", &detail);
    }
    let mark = if r.gw_loss > 0.0 || r.gw_ms > 40 {
        Mark::Slow
    } else {
        Mark::Up
    };
    hop("router", "路由器", mark, r.gw_ms, "ms", &detail)
}

fn judge_dns(r: &Readings) -> Hop {
    let detail = dns_detail(r);
    if !r.has_dns || !r.dns_ok || r.dns_ms >= 1000 {
        return hop("dns", "DNS", Mark::Down, 0, "ms", &detail);
    }
    let mark = if r.dns_ms > 200 { Mark::Slow } else { Mark::Up };
    hop("dns", "DNS", mark, r.dns_ms, "ms", &detail)
}

fn judge_proxy(r: &Readings) -> Hop {
    let detail = proxy_detail(r);
    if !r.proxy_on {
        return hop("proxy", "代理", Mark::Up, 0, "ms", &detail);
    }
    if !r.proxy_accepting {
        return hop("proxy", "代理", Mark::Down, 0, "ms", &detail);
    }
    // The proxy accepted the socket, but traffic only leaves when the direct path is fine
    // and the proxy itself fails to fetch. That break belongs on this row.
    if r.via_tested && !r.via_ok && r.direct_ok {
        return hop("proxy", "代理", Mark::Down, 0, "ms", &detail);
    }
    if proxy_is_slow(r) {
        return hop("proxy", "代理", Mark::Slow, r.via_ms, "ms", &detail);
    }
    let number = if r.via_ok {
        r.via_ms
    } else if r.proxy_connect_ms > 0 {
        r.proxy_connect_ms
    } else {
        1
    };
    hop("proxy", "代理", Mark::Up, number, "ms", &detail)
}

fn proxy_is_slow(r: &Readings) -> bool {
    if !r.via_ok {
        return false;
    }
    if r.via_ms > 800 {
        return true;
    }
    // Direct is quick and the proxy takes the long way around.
    r.direct_ok && r.via_ms > 400 && r.via_ms > r.direct_ms.saturating_add(300)
}

fn wan_mark(r: &Readings) -> (Mark, i64) {
    if r.direct_ok {
        let lossy = r.dest_loss > 0.0 && r.dest_loss < 100.0;
        let mark = if r.direct_ms > 400 || lossy {
            Mark::Slow
        } else {
            Mark::Up
        };
        return (mark, r.direct_ms);
    }
    if r.via_ok {
        let mark = if r.via_ms > 800 { Mark::Slow } else { Mark::Up };
        return (mark, r.via_ms);
    }
    (Mark::Down, 0)
}

fn judge_wan(r: &Readings) -> Hop {
    let (mark, number) = wan_mark(r);
    let detail = if r.wan_traced {
        wan::summarize(
            &r.wan_target,
            r.direct_ok,
            r.via_ok,
            &r.wan_hops,
            r.dest_loss,
        )
    } else {
        wan_detail(r)
    };
    hop("wan", "外网", mark, number, "ms", &detail)
}

fn format_bps(bps: i64) -> String {
    if bps >= 1_000_000 {
        let mb = bps as f64 / 1_000_000.0;
        if mb >= 10.0 {
            format!("{mb:.0} MB/s")
        } else {
            format!("{mb:.1} MB/s")
        }
    } else {
        format!("{} KB/s", bps / 1_000)
    }
}

fn computer_detail(r: &Readings) -> String {
    if !r.loop_ok {
        return "本机回环没有回应".to_string();
    }
    let mut line = if r.computer_name.is_empty() {
        "本机".to_string()
    } else {
        r.computer_name.clone()
    };
    if r.tx_bps > 50_000 || r.rx_bps > 50_000 {
        line = format!(
            "{line} · 发出 {} · 收到 {}",
            format_bps(r.tx_bps),
            format_bps(r.rx_bps)
        );
    }
    line
}

fn air_poor(r: &Readings) -> bool {
    let noisy =
        r.noise_valid && r.rssi_valid && r.rssi < 0 && r.noise < 0 && (r.rssi - r.noise) < 15;
    let crawling = r.tx_mbps > 0 && r.tx_mbps < 24;
    noisy || crawling
}

fn nic_detail(r: &Readings) -> String {
    if r.link_local {
        return "没有从路由器拿到地址".to_string();
    }
    if !r.nic_up {
        return "没有拿到地址".to_string();
    }
    let kind = if r.nic_wifi {
        if r.nic_label.is_empty() {
            "Wi-Fi".to_string()
        } else {
            r.nic_label.clone()
        }
    } else if r.nic_label.is_empty() {
        "有线".to_string()
    } else {
        r.nic_label.clone()
    };
    let mut line = if r.nic_ip.is_empty() {
        kind
    } else {
        format!("{} · {kind}", r.nic_ip)
    };
    if r.nic_wifi {
        let radio = band_channel(&r.band, r.channel);
        if !radio.is_empty() {
            line = format!("{line} · {radio}");
        }
    }
    if r.nic_wifi && r.noise_valid && r.noise < 0 {
        line = format!("{line} · 噪声 {}", r.noise);
    }
    if r.nic_wifi && r.tx_mbps > 0 {
        line = format!("{line} · {} Mbps", r.tx_mbps);
    }
    line
}

fn router_detail(r: &Readings) -> String {
    if !r.has_gw || r.gateway.is_empty() {
        return "没有默认网关".to_string();
    }
    let replied = r.gw_replied && r.gw_loss < 50.0;
    if !replied {
        return format!("{} 没有回应", r.gateway);
    }
    if r.gw_loss > 0.0 {
        format!("{} · 丢包 {:.0}%", r.gateway, r.gw_loss)
    } else {
        r.gateway.clone()
    }
}

fn dns_detail(r: &Readings) -> String {
    if !r.has_dns || r.dns_server.is_empty() {
        return "没有配置 DNS".to_string();
    }
    if !r.dns_ok || r.dns_ms >= 1000 {
        format!("{} 没有解析", r.dns_server)
    } else {
        r.dns_server.clone()
    }
}

fn proxy_detail(r: &Readings) -> String {
    if !r.proxy_on {
        if r.local_proxy_port > 0 {
            let mut line = format!("系统代理关着，本机 {} 在听", r.local_proxy_port);
            if !r.clash_mode.is_empty() {
                line = format!("{line} · {}", r.clash_mode);
            }
            return line;
        }
        return "直连".to_string();
    }
    let addr = if r.proxy_address.is_empty() {
        "代理".to_string()
    } else {
        r.proxy_address.clone()
    };
    let line = if !r.proxy_accepting {
        format!("{addr} 没有在听")
    } else if r.via_tested && !r.via_ok && r.direct_ok {
        format!("{addr} 没有把流量送出去")
    } else {
        addr
    };
    if r.clash_mode.is_empty() {
        line
    } else {
        format!("{line} · {}", r.clash_mode)
    }
}

fn wan_detail(r: &Readings) -> String {
    if r.direct_ok {
        if r.wan_target.is_empty() {
            "外网地址".to_string()
        } else {
            r.wan_target.clone()
        }
    } else if r.via_ok {
        "经代理出去".to_string()
    } else {
        "223.5.5.5 和 1.1.1.1 都没有回应".to_string()
    }
}

fn conclusion_for(hop: &Hop) -> String {
    let verb = if hop.mark == "断" { "断" } else { "慢" };
    // Keep a space before a Latin name so “DNS” doesn’t sit against the character.
    let name = if hop.name.chars().all(|c| c.is_ascii()) {
        format!(" {}", hop.name)
    } else {
        hop.name.clone()
    };
    format!("出网{verb}在{name}。")
}

fn segment_book(hop: &Hop) -> Option<wan::Playbook> {
    let id = match hop.id.as_str() {
        "nic" if hop.detail.contains("没有从路由器拿到地址") => "nic-address",
        "nic" if hop.mark == "断" => "nic-down",
        "nic" if hop.unit == "Mbps" => "nic-cable",
        "nic" if hop.mark == "慢" && hop.unit == "dBm" && hop.number <= -75 => "nic-weak",
        "nic" if hop.mark == "慢" => "nic-air",
        "dns" if hop.mark == "断" => "dns-down",
        "dns" if hop.mark == "慢" => "dns-slow",
        "proxy" if hop.mark == "断" => "proxy-down",
        "proxy" if hop.mark == "慢" => "proxy-slow",
        _ => return None,
    };
    Some(wan::playbook(id))
}

fn next_for(hop: &Hop) -> String {
    if hop.id == "computer" && hop.detail.contains("两块网卡") {
        return "本机地址和另一台设备撞了。改掉重复的地址后再测。".to_string();
    }
    if hop.id == "router" && hop.detail.contains("两块网卡") {
        return "网关地址有两台设备在应答。只留一台路由器后再测。".to_string();
    }
    if hop.detail.contains("硬件地址变了") {
        return "网关的设备变了。等它稳定，或重启路由器后再测。".to_string();
    }
    if let Some(book) = segment_book(hop) {
        return book.check_first;
    }
    if hop.id == "computer"
        && hop.mark == "慢"
        && (hop.detail.contains("发出") || hop.detail.contains("收到"))
    {
        return "这台电脑正在占带宽。先停掉正在下载的程序后再测。".to_string();
    }
    match (hop.id.as_str(), hop.mark.as_str(), hop.unit.as_str()) {
        ("computer", "断", _) => "网络栈没有回应。重启这台电脑后再测。",
        ("computer", _, _) => "这台电脑自己在拖时间。关掉占满系统的程序后再测。",
        ("router", "断", _) => "路由器没有回应。看一下它是否通电，或重启路由器。",
        ("router", _, _) => "路由器回应慢。重启一次路由器。",
        ("wan", "断", _) => "前面都过了，外网没有回应。重启光猫，或过几分钟再测。",
        _ => "外网本身慢。过几分钟再测。",
    }
    .to_string()
}

fn run_cmd(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn usable_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 80
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '%'))
}

fn parse_ping(output: &str) -> (f64, f64) {
    let mut loss = 100.0f64;
    let mut avg = 0.0f64;
    for line in output.lines() {
        if line.contains("packet loss") {
            if let Some(pos) = line.find('%') {
                if let Some(num) = line[..pos].split_whitespace().last() {
                    loss = num.parse().unwrap_or(100.0);
                }
            }
        }
        if line.contains("min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                if let Some(avg_str) = stats.split('/').nth(1) {
                    avg = avg_str.trim().parse().unwrap_or(0.0);
                }
            }
        }
    }
    if loss >= 100.0 {
        avg = 0.0;
    }
    (avg, loss)
}

fn ping(target: &str, count: u8, wait_ms: u32) -> (f64, f64) {
    if !usable_host(target) {
        return (0.0, 100.0);
    }
    let count = count.to_string();
    let wait = wait_ms.to_string();
    let output = run_cmd("ping", &["-c", &count, "-W", &wait, target]);
    parse_ping(&output)
}

fn ping_measured(target: &str, count: u8, wait_ms: u32) -> Option<f64> {
    if !usable_host(target) {
        return None;
    }
    let count = count.to_string();
    let wait = wait_ms.to_string();
    let output = run_cmd("ping", &["-c", &count, "-W", &wait, target]);
    if !output.contains("packet loss") {
        return None;
    }
    Some(parse_ping(&output).1)
}

fn replied(avg: f64, loss: f64) -> bool {
    loss < 100.0 && (avg > 0.0 || loss == 0.0)
}

fn get_primary_interface() -> (String, String) {
    let route = run_cmd("route", &["-n", "get", "default"]);
    let mut iface = String::new();
    let mut gateway = String::new();
    for line in route.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("interface:") {
            iface = rest.trim().to_string();
        } else if let Some(rest) = t.strip_prefix("gateway:") {
            gateway = rest.trim().to_string();
        }
    }
    (iface, gateway)
}

fn hardware_port_for(iface: &str) -> String {
    if iface.is_empty() {
        return String::new();
    }
    let out = run_cmd("networksetup", &["-listallhardwareports"]);
    let mut port = String::new();
    for line in out.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix("Hardware Port:") {
            port = name.trim().to_string();
        } else if let Some(dev) = t.strip_prefix("Device:") {
            if dev.trim() == iface {
                return port;
            }
        }
    }
    String::new()
}

fn is_wifi_port(port: &str) -> bool {
    let p = port.to_lowercase();
    p.contains("wi-fi") || p.contains("wifi") || p.contains("airport")
}

fn link_active(ifconfig: &str) -> bool {
    let has_status = ifconfig.lines().any(|l| l.trim().starts_with("status:"));
    if has_status {
        ifconfig.lines().any(|l| l.trim() == "status: active")
    } else {
        has_ipv4(ifconfig)
    }
}

fn has_ipv4(ifconfig: &str) -> bool {
    !ipv4_addr(ifconfig).is_empty()
}

fn ipv4_addr(ifconfig: &str) -> String {
    for line in ifconfig.lines() {
        let t = line.trim();
        if t.starts_with("inet ") && !t.contains("127.0.0.1") {
            return t.split_whitespace().nth(1).unwrap_or("").to_string();
        }
    }
    String::new()
}

fn computer_name() -> String {
    let name = run_cmd("scutil", &["--get", "ComputerName"]);
    let name = name.trim();
    if !name.is_empty() {
        return name.to_string();
    }
    let host = run_cmd("hostname", &["-s"]);
    let host = host.trim();
    if host.is_empty() {
        String::new()
    } else {
        host.to_string()
    }
}

fn wifi_ssid(iface: &str) -> String {
    if iface.is_empty() {
        return String::new();
    }
    let out = run_cmd("networksetup", &["-getairportnetwork", iface]);
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix("Current Wi-Fi Network:") {
            let name = rest.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    String::new()
}

fn media_mbps(ifconfig: &str) -> i64 {
    for line in ifconfig.lines() {
        let t = line.trim();
        let rest = t
            .strip_prefix("media:")
            .or_else(|| t.strip_prefix("link rate:"))
            .unwrap_or("");
        if rest.is_empty() && !t.starts_with("media:") && !t.contains("link rate:") {
            continue;
        }
        let source = if rest.is_empty() { t } else { rest };
        let bytes = source.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let num: i64 = source[start..i].parse().unwrap_or(0);
                let after = source[i..].to_ascii_lowercase();
                if num > 0 && (after.starts_with("base") || after.trim_start().starts_with("mbps"))
                {
                    return num;
                }
            } else {
                i += 1;
            }
        }
    }
    0
}

fn first_lan_iface() -> String {
    let list = run_cmd("ifconfig", &["-l"]);
    for name in list.split_whitespace() {
        if name == "lo0"
            || name.starts_with("utun")
            || name.starts_with("awdl")
            || name.starts_with("llw")
            || name.starts_with("bridge")
            || name.starts_with("gif")
            || name.starts_with("stf")
        {
            continue;
        }
        let dump = run_cmd("ifconfig", &[name]);
        if link_active(&dump) && has_ipv4(&dump) {
            return name.to_string();
        }
    }
    String::new()
}

fn dns_servers() -> Vec<String> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let from_file = nameservers_from_lines(resolv.lines().filter_map(|l| {
        let t = l.trim();
        t.strip_prefix("nameserver").map(str::trim)
    }));
    if !from_file.is_empty() {
        return from_file;
    }
    let out = run_cmd("scutil", &["--dns"]);
    let mut in_first = false;
    let mut found = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("resolver #") {
            if in_first {
                break;
            }
            in_first = t.starts_with("resolver #1");
            continue;
        }
        if in_first {
            if let Some(rest) = t.strip_prefix("nameserver[") {
                if let Some(ip) = rest.split(':').nth(1) {
                    found.push(ip.trim());
                }
            }
        }
    }
    nameservers_from_lines(found)
}

fn nameservers_from_lines<'a>(items: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let all: Vec<String> = items
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("fe80") && usable_host(s))
        .map(str::to_string)
        .collect();
    let v4: Vec<String> = all.iter().filter(|s| !s.contains(':')).cloned().collect();
    if v4.is_empty() {
        all
    } else {
        v4
    }
}

fn parse_query_time(output: &str) -> Option<f64> {
    for line in output.lines() {
        if let Some(pos) = line.find("Query time:") {
            let rest = line[pos + "Query time:".len()..].trim();
            let n: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(v) = n.parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

fn dns_failed(text: &str) -> bool {
    text.contains("timed out")
        || text.contains("no servers could be reached")
        || text.contains("connection refused")
        || text.contains("communications error")
}

fn dns_probe(server: &str) -> (bool, i64) {
    if !usable_host(server) {
        return (false, 0);
    }
    let at = format!("@{server}");
    let mut args = vec!["+time=2", "+tries=1", "+stats", "baidu.com", at.as_str()];
    if !server.contains(':') {
        args.insert(0, "-4");
    }
    let dig = run_cmd("dig", &args);
    if !dig.is_empty() {
        if dns_failed(&dig) {
            return (false, 0);
        }
        if let Some(ms) = parse_query_time(&dig) {
            return (true, shown_ms(ms));
        }
    }
    let start = Instant::now();
    let output = run_cmd("nslookup", &["baidu.com", server]);
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    if output.contains("can't find")
        || output.contains("NXDOMAIN")
        || output.is_empty()
        || dns_failed(&output)
    {
        (false, 0)
    } else {
        (true, shown_ms(elapsed))
    }
}

fn tcp_ms(ip: &str, port: u16, timeout_ms: u64) -> Option<i64> {
    let addr: SocketAddr = format!("{ip}:{port}").parse().ok()?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
    Some(shown_ms(start.elapsed().as_secs_f64() * 1000.0))
}

fn direct_reach() -> (bool, i64, String) {
    let found = std::thread::scope(|s| {
        let handles = [ALI_DNS, CF_DNS]
            .map(|ip| s.spawn(move || tcp_ms(ip, 443, 1500).map(|ms| (ms, ip.to_string()))));
        handles
            .into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .min_by_key(|(ms, _)| *ms)
    });
    if let Some((ms, ip)) = found {
        return (true, ms, ip);
    }
    let (avg, loss) = ping(ALI_DNS, 2, 1000);
    if loss < 50.0 && replied(avg, loss) {
        (true, shown_ms(avg), ALI_DNS.to_string())
    } else {
        (false, 0, String::new())
    }
}

fn curl_cmd() -> Command {
    let mut cmd = Command::new("curl");
    for key in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

fn is_loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

fn port_listening(port: u16) -> bool {
    let spec = format!("-iTCP:{port}");
    let out = run_cmd("lsof", &["-nP", &spec, "-sTCP:LISTEN"]);
    out.lines().skip(1).any(|line| !line.trim().is_empty())
}

fn connect_host_ms(host: &str, port: u16) -> Option<i64> {
    if !usable_host(host) || port == 0 {
        return None;
    }
    let addr = format!("{host}:{port}").to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_millis(2000)).ok()?;
    Some(shown_ms(start.elapsed().as_secs_f64() * 1000.0))
}

fn read_service_proxy(service: &str) -> Option<(String, u16, &'static str)> {
    if service.is_empty() {
        return None;
    }
    for (flag, kind) in [
        ("-getwebproxy", "http"),
        ("-getsecurewebproxy", "https"),
        ("-getsocksfirewallproxy", "socks"),
    ] {
        let out = run_cmd("networksetup", &[flag, service]);
        let mut enabled = false;
        let mut server = String::new();
        let mut port = 0u16;
        for line in out.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("Enabled:") {
                let v = rest.trim().to_lowercase();
                enabled = v.contains("yes") || v == "on";
            } else if let Some(rest) = t.strip_prefix("Server:") {
                server = rest.trim().to_string();
            } else if let Some(rest) = t.strip_prefix("Port:") {
                port = rest.trim().parse().unwrap_or(0);
            }
        }
        if enabled && usable_host(&server) && server != "(null)" && port > 0 {
            return Some((server, port, kind));
        }
    }
    None
}

fn system_proxy(service: &str) -> Option<(String, u16, &'static str)> {
    let mut names: Vec<&str> = Vec::new();
    if !service.is_empty() {
        names.push(service);
    }
    for fallback in ["Wi-Fi", "Ethernet"] {
        if !names.contains(&fallback) {
            names.push(fallback);
        }
    }
    for name in names {
        if let Some(found) = read_service_proxy(name) {
            return Some(found);
        }
    }
    None
}

struct ProxyPath {
    on: bool,
    accepting: bool,
    connect_ms: i64,
    kind: String,
    address: String,
    /// A common local proxy port that is listening while the system proxy is off.
    local_port: u16,
    clash_mode: String,
}

fn proxy_closed() -> ProxyPath {
    ProxyPath {
        on: false,
        accepting: false,
        connect_ms: 0,
        kind: String::new(),
        address: String::new(),
        local_port: 0,
        clash_mode: String::new(),
    }
}

/// Ports seen on Clash, V2Ray, and the local listeners this sheet already knows.
const LOCAL_PROXY_PORTS: &[u16] = &[7897, 7890, 7893, 1080, 1087, 20171];
const CLASH_API_PORTS: &[u16] = &[9090, 9097];

fn find_local_proxy_port() -> Option<u16> {
    let open = std::thread::scope(|scope| {
        let handles: Vec<_> = LOCAL_PROXY_PORTS
            .iter()
            .copied()
            .map(|port| scope.spawn(move || port_listening(port)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or(false))
            .collect::<Vec<_>>()
    });
    LOCAL_PROXY_PORTS
        .iter()
        .copied()
        .zip(open)
        .find(|(_, listening)| *listening)
        .map(|(port, _)| port)
}

fn clash_mode_from_body(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    match value.get("mode").and_then(|item| item.as_str())? {
        "rule" => Some("规则模式".to_string()),
        "global" => Some("全局模式".to_string()),
        "direct" => Some("直连模式".to_string()),
        _ => None,
    }
}

/// Read only the mode field from the local Clash API. The rest of the body is dropped.
fn clash_mode() -> String {
    let bodies = std::thread::scope(|scope| {
        let handles: Vec<_> = CLASH_API_PORTS
            .iter()
            .copied()
            .map(|port| {
                scope.spawn(move || {
                    let url = format!("http://127.0.0.1:{port}/configs");
                    let mut cmd = curl_cmd();
                    cmd.args(["-s", "--max-time", "1", "--noproxy", "*", &url]);
                    cmd.output()
                        .ok()
                        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
                        .unwrap_or_default()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_default())
            .collect::<Vec<_>>()
    });
    for body in bodies {
        if let Some(mode) = clash_mode_from_body(&body) {
            return mode;
        }
    }
    String::new()
}

fn inspect_proxy_path() -> ProxyPath {
    let (iface, _) = get_primary_interface();
    let service = hardware_port_for(&iface);
    let Some((host, port, kind)) = system_proxy(&service) else {
        let local_port = find_local_proxy_port().unwrap_or(0);
        let mut closed = proxy_closed();
        if local_port > 0 {
            closed.local_port = local_port;
            closed.clash_mode = clash_mode();
        }
        return closed;
    };
    let connect_ms = connect_host_ms(&host, port).unwrap_or(0);
    let accepting = if is_loopback(&host) {
        port_listening(port) || connect_ms > 0
    } else {
        connect_ms > 0
    };
    ProxyPath {
        on: true,
        accepting,
        connect_ms,
        kind: kind.to_string(),
        address: format!("{host}:{port}"),
        local_port: 0,
        clash_mode: clash_mode(),
    }
}

fn proxy_url(kind: &str, address: &str) -> String {
    if kind == "socks" {
        format!("socks5h://{address}")
    } else {
        format!("http://{address}")
    }
}

fn via_proxy(kind: &str, address: &str) -> (bool, i64) {
    if address.is_empty() {
        return (false, 0);
    }
    let proxy = proxy_url(kind, address);
    let mut cmd = curl_cmd();
    cmd.args([
        "-k",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{time_total}",
        "-x",
        &proxy,
        "--connect-timeout",
        "3",
        "--max-time",
        "6",
        "https://1.1.1.1/",
    ]);
    let output = cmd
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut parts = output.split_whitespace();
    let code = parts.next().unwrap_or("");
    let secs: f64 = parts.next().unwrap_or("0").parse().unwrap_or(0.0);
    let ok = code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) && code != "000";
    if ok {
        (true, shown_ms(secs * 1000.0))
    } else {
        (false, 0)
    }
}

const AIRPORT_PATH: &str =
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

struct Radio {
    rssi_valid: bool,
    rssi: i32,
    noise_valid: bool,
    noise: i32,
    tx_mbps: i64,
    band: String,
    channel: u32,
}

fn band_label(raw: &str) -> String {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    match compact.to_ascii_lowercase().as_str() {
        "2.4ghz" => "2.4 GHz".to_string(),
        "5ghz" => "5 GHz".to_string(),
        "6ghz" => "6 GHz".to_string(),
        _ => String::new(),
    }
}

fn band_channel(band: &str, channel: u32) -> String {
    match (band.is_empty(), channel == 0) {
        (true, true) => String::new(),
        (false, false) => format!("{band} · 信道 {channel}"),
        (false, true) => band.to_string(),
        (true, false) => format!("信道 {channel}"),
    }
}

fn wifi_channel(raw: u64) -> u32 {
    if (1..=233).contains(&raw) {
        raw as u32
    } else {
        0
    }
}

fn tx_mbps_from(raw: i64) -> i64 {
    if raw <= 0 {
        0
    } else if raw > 10_000 {
        raw / 1_000_000
    } else {
        raw
    }
}

fn radio_from_json(v: &serde_json::Value) -> Option<Radio> {
    let rssi = v.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let valid = v
        .get("rssiValid")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let noise = v.get("noise").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let tx = v.get("txRate").and_then(|x| x.as_i64()).unwrap_or(0);
    let channel = wifi_channel(v.get("channel").and_then(|x| x.as_u64()).unwrap_or(0));
    let band = band_label(v.get("band").and_then(|x| x.as_str()).unwrap_or(""));
    let rssi_valid = valid && rssi < 0;
    if !rssi_valid && channel == 0 && band.is_empty() {
        return None;
    }
    Some(Radio {
        rssi_valid,
        rssi: if rssi_valid { rssi } else { 0 },
        noise_valid: rssi_valid && noise < 0,
        noise: if rssi_valid { noise } else { 0 },
        tx_mbps: if rssi_valid { tx_mbps_from(tx) } else { 0 },
        band,
        channel,
    })
}

fn airport_channel(text: &str) -> u32 {
    let raw = text
        .lines()
        .find(|line| line.trim().starts_with("channel:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| {
            value
                .split([',', ' '])
                .find(|part| !part.trim().is_empty())
                .and_then(|part| part.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    wifi_channel(raw)
}

fn read_radio(iface: &str, wifi: bool, helpers: &[PathBuf]) -> Radio {
    let empty = Radio {
        rssi_valid: false,
        rssi: 0,
        noise_valid: false,
        noise: 0,
        tx_mbps: 0,
        band: String::new(),
        channel: 0,
    };
    if !wifi || iface.is_empty() {
        return empty;
    }
    for path in helpers {
        if !path.exists() {
            continue;
        }
        let Ok(out) = Command::new(path).arg(iface).output() else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
            continue;
        };
        if let Some(radio) = radio_from_json(&v) {
            return radio;
        }
    }
    let out = run_cmd(AIRPORT_PATH, &["-I"]);
    let rssi = out
        .lines()
        .find(|l| l.trim().starts_with("agrCtlRSSI"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);
    let noise = out
        .lines()
        .find(|l| l.trim().starts_with("agrCtlNoise"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);
    let channel = airport_channel(&out);
    if rssi < 0 || channel > 0 {
        Radio {
            rssi_valid: rssi < 0,
            rssi: if rssi < 0 { rssi } else { 0 },
            noise_valid: rssi < 0 && noise < 0,
            noise: if rssi < 0 { noise } else { 0 },
            tx_mbps: 0,
            band: String::new(),
            channel,
        }
    } else {
        empty
    }
}

struct ArpRow {
    ip: String,
    mac: String,
}

fn arp_entries() -> Vec<ArpRow> {
    let out = run_cmd("arp", &["-a"]);
    let mut rows = Vec::new();
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[1]
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_string();
        let mac = parts[3].to_string();
        if ip.is_empty() || !mac.contains(':') || mac.eq_ignore_ascii_case("(incomplete)") {
            continue;
        }
        rows.push(ArpRow { ip, mac });
    }
    rows
}

fn macs_for<'a>(rows: &'a [ArpRow], ip: &str) -> Vec<&'a str> {
    let mut macs = Vec::new();
    for row in rows {
        if row.ip == ip && !macs.contains(&row.mac.as_str()) {
            macs.push(row.mac.as_str());
        }
    }
    macs
}

fn parse_iface_bytes(text: &str, iface: &str) -> Option<(u64, u64)> {
    if iface.is_empty() {
        return None;
    }
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 || cols[0] != iface || !cols[2].starts_with("<Link") {
            continue;
        }
        let ibytes = cols[6].parse().ok()?;
        let obytes = cols[9].parse().ok()?;
        return Some((ibytes, obytes));
    }
    None
}

fn iface_bytes(iface: &str) -> Option<(u64, u64)> {
    parse_iface_bytes(&run_cmd("netstat", &["-ib", "-I", iface]), iface)
}

struct Watch {
    iface: String,
    gw_ip: String,
    gw_mac: String,
    ibytes: u64,
    obytes: u64,
    at: Instant,
}

static WATCH: Mutex<Option<Watch>> = Mutex::new(None);

fn remember_watch(
    iface: &str,
    gateway: &str,
    gw_mac: &str,
    bytes: Option<(u64, u64)>,
) -> (i64, i64, bool) {
    let now = Instant::now();
    let mut guard = WATCH.lock().unwrap_or_else(|err| err.into_inner());
    let (tx_bps, rx_bps, changed) = if let Some(prev) = guard.as_ref() {
        let secs = now.duration_since(prev.at).as_secs_f64().max(0.2);
        let (rx, tx) = match (bytes, prev.iface == iface) {
            (Some((ibytes, obytes)), true) if ibytes >= prev.ibytes && obytes >= prev.obytes => (
                ((ibytes - prev.ibytes) as f64 / secs) as i64,
                ((obytes - prev.obytes) as f64 / secs) as i64,
            ),
            _ => (0, 0),
        };
        let changed = !prev.gw_mac.is_empty()
            && !gw_mac.is_empty()
            && prev.gw_ip == gateway
            && prev.gw_mac != gw_mac;
        (tx, rx, changed)
    } else {
        (0, 0, false)
    };
    if let Some((ibytes, obytes)) = bytes {
        *guard = Some(Watch {
            iface: iface.to_string(),
            gw_ip: gateway.to_string(),
            gw_mac: gw_mac.to_string(),
            ibytes,
            obytes,
            at: now,
        });
    }
    (tx_bps, rx_bps, changed)
}

fn helper_candidates(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = extra.to_vec();
    paths.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("wifi-helper"),
    );
    paths
}

fn gather(extra_helpers: &[PathBuf], site: &str) -> Readings {
    let (mut iface, gateway) = get_primary_interface();
    if iface.is_empty() {
        iface = first_lan_iface();
    }
    let dump = if iface.is_empty() {
        String::new()
    } else {
        run_cmd("ifconfig", &[&iface])
    };
    let port = hardware_port_for(&iface);
    let nic_wifi = is_wifi_port(&port);
    let nic_ip = ipv4_addr(&dump);
    let link_local = nic_ip.starts_with("169.254.");
    let nic_up = !iface.is_empty() && link_active(&dump) && !nic_ip.is_empty() && !link_local;
    let nic_label = if nic_wifi {
        wifi_ssid(&iface)
    } else {
        port.clone()
    };
    let mbps = if nic_wifi { 0 } else { media_mbps(&dump) };
    let machine = computer_name();
    let helpers = helper_candidates(extra_helpers);
    let radio = read_radio(&iface, nic_wifi, &helpers);
    let dns = dns_servers();
    let dns_server = dns.first().cloned().unwrap_or_default();
    let has_dns = !dns_server.is_empty();
    let has_gw = usable_host(&gateway);

    let (loopback, gateway_ping, dns_result, direct, proxy_path, bytes, arp) =
        std::thread::scope(|s| {
            let t_loop = s.spawn(|| ping("127.0.0.1", 1, 1000));
            let gw = gateway.clone();
            let t_gw = s.spawn(move || {
                if usable_host(&gw) {
                    ping(&gw, 3, 1000)
                } else {
                    (0.0, 100.0)
                }
            });
            let dns_for_probe = dns_server.clone();
            let t_dns = s.spawn(move || {
                if has_dns {
                    dns_probe(&dns_for_probe)
                } else {
                    (false, 0)
                }
            });
            let iface_for_bytes = iface.clone();
            let t_bytes = s.spawn(move || iface_bytes(&iface_for_bytes));
            let t_arp = s.spawn(arp_entries);
            let t_direct = s.spawn(direct_reach);
            let t_proxy = s.spawn(inspect_proxy_path);
            (
                t_loop.join().unwrap_or((0.0, 100.0)),
                t_gw.join().unwrap_or((0.0, 100.0)),
                t_dns.join().unwrap_or((false, 0)),
                t_direct.join().unwrap_or((false, 0, String::new())),
                t_proxy.join().unwrap_or_else(|_| proxy_closed()),
                t_bytes.join().unwrap_or(None),
                t_arp.join().unwrap_or_default(),
            )
        });

    let (via_tested, via_ok, via_ms) = if proxy_path.on && proxy_path.accepting {
        let (ok, ms) = via_proxy(&proxy_path.kind, &proxy_path.address);
        (true, ok, ms)
    } else {
        (false, false, 0)
    };

    let (loop_avg, loop_loss) = loopback;
    let loop_ok = replied(loop_avg, loop_loss);
    let (gw_avg, gw_loss) = gateway_ping;
    let gw_replied = replied(gw_avg, gw_loss);
    let (dns_ok, dns_ms) = dns_result;
    let (direct_ok, direct_ms, wan_target) = direct;
    let trace_target = if wan_target.is_empty() {
        ALI_DNS.to_string()
    } else {
        wan_target.clone()
    };
    let https_host = wan::resolve_site(site).unwrap_or_default();
    let invalid_site = !site.trim().is_empty() && https_host.is_empty();
    let proxy_for_https = if proxy_path.on && proxy_path.accepting {
        proxy_url(&proxy_path.kind, &proxy_path.address)
    } else {
        String::new()
    };
    let (raw_hops, measured_loss, stun, web_ip, https_visit, name_lookup) =
        std::thread::scope(|scope| {
            let target = trace_target.clone();
            let trace = scope.spawn(move || wan::trace_path(&target));
            let target = trace_target.clone();
            let loss = scope.spawn(move || ping_measured(&target, 3, 1000));
            let stun = scope.spawn(wan::stun_map);
            let web = scope.spawn(wan::web_egress);
            let host = https_host.clone();
            let proxy = proxy_for_https.clone();
            let https = scope.spawn(move || {
                if host.is_empty() {
                    (wan::HttpsRaw::not_run(), Vec::new())
                } else {
                    let via = if proxy.is_empty() { None } else { Some(proxy) };
                    let raw = wan::https_probe(&host, via.as_deref());
                    let urls = wan::follow_redirects(&raw.redirect_url, via.as_deref());
                    (raw, urls)
                }
            });
            let host = https_host.clone();
            let lookup = scope.spawn(move || {
                if host.is_empty() {
                    wan::NameLookup::Unchecked
                } else {
                    wan::direct_lookup(&host)
                }
            });
            (
                trace.join().unwrap_or_default(),
                loss.join().unwrap_or(None),
                stun.join().unwrap_or((String::new(), None)),
                web.join().unwrap_or_default(),
                https
                    .join()
                    .unwrap_or_else(|_| (wan::HttpsRaw::not_run(), Vec::new())),
                lookup.join().unwrap_or(wan::NameLookup::Unchecked),
            )
        });
    let (https_raw, redirect_urls) = https_visit;
    let redirect = wan::redirect_fact(&https_host, &redirect_urls);
    let wan_hops = wan::finish_probes(&raw_hops, direct_ok);
    let (mapped_ip, symmetric) = stun;
    let nat_line = wan::nat_fact(&nic_ip, &mapped_ip, &web_ip, symmetric, &wan_hops);
    let (https_kind, https_line) = if invalid_site {
        ("input".to_string(), "网址没法识别".to_string())
    } else {
        wan::classify_https(
            &https_host,
            proxy_path.on && proxy_path.accepting,
            &https_raw,
            name_lookup,
        )
    };
    let dest_loss = measured_loss.unwrap_or(-1.0);
    let gw_macs = macs_for(&arp, &gateway);
    let self_macs = macs_for(&arp, &nic_ip);
    let gw_mac = if gw_macs.len() == 1 {
        gw_macs[0].to_string()
    } else {
        String::new()
    };
    let (tx_bps, rx_bps, gw_mac_changed) = remember_watch(&iface, &gateway, &gw_mac, bytes);

    Readings {
        loop_ok,
        loop_ms: if loop_ok { shown_ms(loop_avg) } else { 0 },
        nic_up,
        nic_wifi,
        rssi: radio.rssi,
        rssi_valid: radio.rssi_valid,
        mbps,
        has_gw,
        gw_replied,
        gw_ms: if gw_replied { shown_ms(gw_avg) } else { 0 },
        gw_loss,
        has_dns,
        dns_ok,
        dns_ms,
        proxy_on: proxy_path.on,
        proxy_accepting: proxy_path.accepting,
        proxy_connect_ms: proxy_path.connect_ms,
        via_tested,
        via_ok,
        via_ms,
        direct_ok,
        direct_ms,
        computer_name: machine,
        nic_ip,
        nic_label,
        gateway,
        dns_server,
        proxy_address: proxy_path.address,
        wan_target,
        link_local,
        noise: radio.noise,
        noise_valid: radio.noise_valid,
        tx_mbps: radio.tx_mbps,
        self_conflict: self_macs.len() > 1,
        gw_conflict: gw_macs.len() > 1,
        gw_mac_changed,
        tx_bps,
        rx_bps,
        wan_hops,
        wan_traced: true,
        dest_loss,
        nat_line,
        https_kind,
        https_line,
        band: radio.band,
        channel: radio.channel,
        local_proxy_port: proxy_path.local_port,
        clash_mode: proxy_path.clash_mode,
        redirect_count: redirect.count,
        redirect_portal: redirect.portal,
    }
}

fn read_chain_now(extra_helpers: &[PathBuf], site: &str) -> Chain {
    judge(&gather(extra_helpers, site))
}

#[tauri::command]
fn read_chain(app: tauri::AppHandle, site: Option<String>) -> Chain {
    use tauri::Manager;
    let mut extra = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        extra.push(dir.join("wifi-helper"));
    }
    read_chain_now(&extra, site.unwrap_or_default().as_str())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![read_chain])
        .run(tauri::generate_context!())
        .expect("error while running Lanwatch");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Readings {
        Readings {
            loop_ok: true,
            loop_ms: 1,
            nic_up: true,
            nic_wifi: true,
            rssi: -55,
            rssi_valid: true,
            mbps: 0,
            has_gw: true,
            gw_replied: true,
            gw_ms: 4,
            gw_loss: 0.0,
            has_dns: true,
            dns_ok: true,
            dns_ms: 18,
            proxy_on: false,
            proxy_accepting: false,
            proxy_connect_ms: 0,
            via_tested: false,
            via_ok: false,
            via_ms: 0,
            direct_ok: true,
            direct_ms: 28,
            computer_name: "测试机".to_string(),
            nic_ip: "192.168.1.20".to_string(),
            nic_label: "家里".to_string(),
            gateway: "192.168.1.1".to_string(),
            dns_server: "223.5.5.5".to_string(),
            proxy_address: String::new(),
            wan_target: "223.5.5.5".to_string(),
            link_local: false,
            noise: -95,
            noise_valid: false,
            tx_mbps: 0,
            self_conflict: false,
            gw_conflict: false,
            gw_mac_changed: false,
            tx_bps: 0,
            rx_bps: 0,
            wan_hops: Vec::new(),
            wan_traced: false,
            dest_loss: -1.0,
            nat_line: String::new(),
            https_kind: String::new(),
            https_line: String::new(),
            band: String::new(),
            channel: 0,
            local_proxy_port: 0,
            clash_mode: String::new(),
            redirect_count: 0,
            redirect_portal: false,
        }
    }

    fn marks(chain: &Chain) -> Vec<&str> {
        chain.hops.iter().map(|h| h.mark.as_str()).collect()
    }

    #[test]
    fn clear_path_is_one_sentence() {
        let chain = judge(&healthy());
        assert_eq!(
            chain
                .hops
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>(),
            vec!["这台电脑", "网卡", "路由器", "DNS", "代理", "外网"]
        );
        assert_eq!(marks(&chain), vec!["通", "通", "通", "通", "通", "通"]);
        assert_eq!(chain.conclusion, "从这台电脑到外网是通的。");
        assert_eq!(chain.next, "不用做什么。");
        assert_eq!(chain.problem_id, "");
        assert!(chain.playbook.is_none());
        assert!(chain.wan.hops.is_empty());
        assert!(chain.wan.https.is_empty());
        assert_eq!(chain.hops[4].number, 0);
        assert_eq!(
            chain
                .hops
                .iter()
                .map(|h| h.detail.as_str())
                .collect::<Vec<_>>(),
            vec![
                "测试机",
                "192.168.1.20 · 家里",
                "192.168.1.1",
                "223.5.5.5",
                "直连",
                "223.5.5.5",
            ]
        );
    }

    #[test]
    fn first_break_is_the_router_even_if_later_hops_fail() {
        let mut r = healthy();
        r.gw_replied = false;
        r.gw_loss = 100.0;
        r.gw_ms = 0;
        r.dns_ok = false;
        r.dns_ms = 0;
        r.direct_ok = false;
        r.direct_ms = 0;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "router");
        assert_eq!(chain.conclusion, "出网断在路由器。");
        assert_eq!(
            chain.next,
            "路由器没有回应。看一下它是否通电，或重启路由器。"
        );
        assert_eq!(chain.hops[2].mark, "断");
        assert_eq!(chain.hops[2].number, 0);
    }

    #[test]
    fn a_break_beats_an_earlier_slow_hop() {
        let mut r = healthy();
        r.rssi = -82;
        r.gw_replied = false;
        r.gw_loss = 100.0;
        let chain = judge(&r);
        assert_eq!(chain.hops[1].mark, "慢");
        assert_eq!(chain.problem_id, "router");
    }

    #[test]
    fn nic_down_is_named_before_the_router() {
        let mut r = healthy();
        r.nic_up = false;
        r.gw_replied = false;
        r.gw_loss = 100.0;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "nic");
        assert_eq!(chain.conclusion, "出网断在网卡。");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "nic-down");
        assert_eq!(chain.next, book.check_first);
        assert!(book.look_at.iter().any(|item| item.contains("地址")));
        assert!(book
            .never_auto
            .iter()
            .all(|item| item.starts_with("不要自动")));
    }

    #[test]
    fn weak_wifi_is_slow_and_keeps_the_signal() {
        let mut r = healthy();
        r.rssi = -80;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "nic");
        assert_eq!(chain.hops[1].mark, "慢");
        assert_eq!(chain.hops[1].number, -80);
        assert_eq!(chain.hops[1].unit, "dBm");
        assert_eq!(chain.conclusion, "出网慢在网卡。");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "nic-weak");
        assert_eq!(chain.next, book.check_first);
        assert!(book.look_at.iter().any(|item| item.contains("信道")));
        assert!(!chain.next.contains("改成 223.5.5.5"));
    }

    #[test]
    fn slow_ethernet_asks_for_the_cable() {
        let mut r = healthy();
        r.nic_wifi = false;
        r.rssi_valid = false;
        r.mbps = 10;
        let chain = judge(&r);
        assert_eq!(chain.hops[1].mark, "慢");
        assert_eq!(chain.hops[1].number, 10);
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "nic-cable");
        assert_eq!(chain.next, book.check_first);
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动重启光猫")));
    }

    #[test]
    fn dns_failure_leaves_the_outside_alone() {
        let mut r = healthy();
        r.dns_ok = false;
        r.dns_ms = 0;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "dns");
        assert_eq!(chain.conclusion, "出网断在 DNS。");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "dns-down");
        assert_eq!(chain.next, book.check_first);
        assert!(!chain.next.contains("改成 223.5.5.5"));
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动把 DNS 改成 223.5.5.5")));
        assert_eq!(chain.hops[5].mark, "通");
    }

    #[test]
    fn slow_dns_uses_the_query_time() {
        let mut r = healthy();
        r.dns_ms = 350;
        let chain = judge(&r);
        assert_eq!(chain.hops[3].mark, "慢");
        assert_eq!(chain.hops[3].number, 350);
        assert_eq!(chain.conclusion, "出网慢在 DNS。");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "dns-slow");
        assert_eq!(chain.next, book.check_first);
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动关掉系统代理")));
    }

    #[test]
    fn missing_dns_server_is_down() {
        let mut r = healthy();
        r.has_dns = false;
        r.dns_ok = false;
        let chain = judge(&r);
        assert_eq!(chain.hops[3].mark, "断");
        assert_eq!(chain.hops[3].number, 0);
    }

    #[test]
    fn dead_local_proxy_is_the_break_when_the_line_is_up() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = false;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "proxy");
        assert_eq!(chain.hops[4].mark, "断");
        assert_eq!(chain.hops[5].mark, "通");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "proxy-down");
        assert_eq!(chain.next, book.check_first);
        assert!(!chain.next.contains("关掉系统代理"));
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动关掉系统代理")));
    }

    #[test]
    fn proxy_that_does_not_forward_is_down() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.proxy_connect_ms = 2;
        r.via_tested = true;
        r.via_ok = false;
        r.direct_ok = true;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "proxy");
        assert_eq!(chain.hops[4].mark, "断");
        assert_eq!(chain.hops[5].mark, "通");
    }

    #[test]
    fn proxy_much_slower_than_the_line_is_slow() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.via_tested = true;
        r.via_ok = true;
        r.via_ms = 619;
        r.direct_ms = 24;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "proxy");
        assert_eq!(chain.hops[4].mark, "慢");
        assert_eq!(chain.hops[4].number, 619);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.conclusion, "出网慢在代理。");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "proxy-slow");
        assert!(!book.check_first.contains("关掉系统代理"));
        assert!(book.never_auto.iter().any(|item| item.contains("不要自动")));
    }

    #[test]
    fn slow_proxy_keeps_the_direct_outside() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.via_tested = true;
        r.via_ok = true;
        r.via_ms = 1200;
        r.direct_ms = 40;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "proxy");
        assert_eq!(chain.hops[4].mark, "慢");
        assert_eq!(chain.hops[4].number, 1200);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.hops[5].number, 40);
        assert_eq!(chain.conclusion, "出网慢在代理。");
    }

    #[test]
    fn proxy_is_the_only_way_out() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.via_tested = true;
        r.via_ok = true;
        r.via_ms = 220;
        r.direct_ok = false;
        r.direct_ms = 0;
        let chain = judge(&r);
        assert_eq!(marks(&chain), vec!["通", "通", "通", "通", "通", "通"]);
        assert_eq!(chain.hops[4].number, 220);
        assert_eq!(chain.hops[5].number, 220);
        assert_eq!(chain.problem_id, "");
    }

    #[test]
    fn outside_is_down_when_neither_path_answers() {
        let mut r = healthy();
        r.direct_ok = false;
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.proxy_connect_ms = 3;
        r.via_tested = true;
        r.via_ok = false;
        let chain = judge(&r);
        assert_eq!(chain.hops[4].mark, "通");
        assert_eq!(chain.problem_id, "wan");
        assert_eq!(chain.conclusion, "出网断在外网。");
        assert_eq!(chain.next, wan::playbook("wan-down").check_first);
        assert!(chain.next.contains("不是证书问题"));
        assert!(chain
            .playbook
            .unwrap()
            .never_auto
            .iter()
            .any(|line| line.contains("不要自动重启光猫")));
    }

    #[test]
    fn slow_outside_is_named_when_nothing_else_is() {
        let mut r = healthy();
        r.direct_ms = 510;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "wan");
        assert_eq!(chain.hops[5].mark, "慢");
        assert_eq!(chain.conclusion, "出网慢在外网。");
        assert_eq!(chain.next, wan::playbook("wan-slow").check_first);
    }

    fn sample_hops() -> Vec<wan::WanHop> {
        vec![
            wan::WanHop {
                ttl: 1,
                ip: "192.168.1.1".into(),
                ms: 2,
                loss: 0,
                kind: "ok".into(),
                asn: String::new(),
                asn_name: String::new(),
                note: "192.168.1.1".into(),
            },
            wan::WanHop {
                ttl: 4,
                ip: "203.0.113.9".into(),
                ms: 21,
                loss: 0,
                kind: "ok".into(),
                asn: "AS4134".into(),
                asn_name: "CHINANET-BACKBONE".into(),
                note: "AS4134".into(),
            },
        ]
    }

    #[test]
    fn traced_outside_keeps_the_mark_and_adds_hop_nat_and_certificate_facts() {
        let mut r = healthy();
        r.wan_traced = true;
        r.wan_hops = sample_hops();
        r.dest_loss = 0.0;
        r.nat_line = "NAT 192.168.1.20 → 203.0.113.8".into();
        r.https_kind = "ok".into();
        r.https_line = "www.baidu.com · 证书正常".into();
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.problem_id, "");
        assert!(chain.playbook.is_none());
        assert_eq!(
            chain.hops[5].detail,
            "223.5.5.5 · 2 跳 · 终点丢包 0% · AS4134 CHINANET-BACKBONE"
        );
        assert_eq!(chain.wan.nat, "NAT 192.168.1.20 → 203.0.113.8");
        assert_eq!(chain.wan.https_kind, "ok");
        assert_eq!(chain.wan.hops.len(), 2);
        assert_eq!(chain.conclusion, "从这台电脑到外网是通的。");
    }

    #[test]
    fn destination_loss_slows_the_outside_without_calling_it_a_certificate() {
        let mut r = healthy();
        r.wan_traced = true;
        r.dest_loss = 33.0;
        r.https_kind = "ok".into();
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "慢");
        assert_eq!(chain.problem_id, "wan");
        assert_eq!(chain.conclusion, "出网慢在外网。");
        assert_eq!(chain.playbook.unwrap().id, "wan-loss");
        assert!(chain.hops[5].detail.contains("终点丢包 33%"));
    }

    #[test]
    fn a_bad_certificate_stays_up_and_is_not_a_dead_path() {
        let mut r = healthy();
        r.https_kind = "cert".into();
        r.https_line = "pay.example · 证书过期 · 连得上".into();
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.problem_id, "wan");
        assert_eq!(chain.conclusion, "外网是通的。打不开是证书问题。");
        assert_eq!(chain.wan.https, "pay.example · 证书过期 · 连得上");
        assert_eq!(chain.playbook.unwrap().id, "wan-cert");
        assert!(!chain.next.contains("重启光猫"));
    }

    #[test]
    fn an_unreachable_site_is_not_described_as_a_certificate() {
        let mut r = healthy();
        r.https_kind = "down".into();
        r.https_line = "pay.example · 连不上".into();
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.conclusion, "外网是通的。这个网址连不上。");
        assert!(!chain.conclusion.contains("证书"));
        assert_eq!(chain.playbook.unwrap().id, "wan-site");
    }

    #[test]
    fn an_earlier_break_keeps_the_conclusion_when_the_certificate_also_fails() {
        let mut r = healthy();
        r.gw_replied = false;
        r.gw_loss = 100.0;
        r.https_kind = "cert".into();
        r.https_line = "pay.example · 证书过期 · 连得上".into();
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "router");
        assert_eq!(chain.conclusion, "出网断在路由器。");
        assert!(chain.playbook.is_none());
        assert_eq!(chain.wan.https_kind, "cert");
    }

    #[test]
    fn proxy_path_labels_the_direct_hops() {
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.via_tested = true;
        r.via_ok = true;
        r.via_ms = 220;
        r.direct_ok = false;
        r.direct_ms = 0;
        r.wan_traced = true;
        r.wan_hops = vec![wan::WanHop {
            ttl: 3,
            ip: String::new(),
            ms: 0,
            loss: 0,
            kind: "down".into(),
            asn: String::new(),
            asn_name: String::new(),
            note: "中断".into(),
        }];
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.hops[5].detail, "经代理出去 · 直连在第 3 跳中断");
        assert_eq!(chain.wan.path, "直连");
        assert_eq!(chain.problem_id, "");
    }

    #[test]
    fn earliest_slow_hop_wins() {
        let mut r = healthy();
        r.rssi = -78;
        r.direct_ms = 600;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "nic");
    }

    #[test]
    fn computer_comes_first() {
        let mut r = healthy();
        r.loop_ok = false;
        r.nic_up = false;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "computer");
        assert_eq!(chain.conclusion, "出网断在这台电脑。");
        assert_eq!(chain.next, "网络栈没有回应。重启这台电脑后再测。");
    }

    #[test]
    fn router_loss_without_a_full_drop_is_slow() {
        let mut r = healthy();
        r.gw_loss = 33.0;
        r.gw_ms = 6;
        let chain = judge(&r);
        assert_eq!(chain.hops[2].mark, "慢");
        assert_eq!(chain.hops[2].number, 6);
        assert_eq!(chain.next, "路由器回应慢。重启一次路由器。");
    }

    #[test]
    fn ping_parser_reads_macos_output() {
        let sample = "\
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.101/2.504/4.002/0.900 ms
";
        let (avg, loss) = parse_ping(sample);
        assert!((avg - 2.504).abs() < 0.001);
        assert!((loss - 0.0).abs() < 0.001);
    }

    #[test]
    fn address_clash_on_this_computer_is_the_break() {
        let mut r = healthy();
        r.self_conflict = true;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "computer");
        assert_eq!(chain.hops[0].mark, "断");
        assert_eq!(chain.hops[0].detail, "本机地址有两块网卡");
        assert_eq!(
            chain.next,
            "本机地址和另一台设备撞了。改掉重复的地址后再测。"
        );
    }

    #[test]
    fn gateway_clash_lands_on_the_router() {
        let mut r = healthy();
        r.gw_conflict = true;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "router");
        assert_eq!(chain.hops[2].detail, "192.168.1.1 有两块网卡");
        assert_eq!(
            chain.next,
            "网关地址有两台设备在应答。只留一台路由器后再测。"
        );
    }

    #[test]
    fn gateway_hardware_change_is_slow() {
        let mut r = healthy();
        r.gw_mac_changed = true;
        let chain = judge(&r);
        assert_eq!(chain.hops[2].mark, "慢");
        assert!(chain.hops[2].detail.contains("硬件地址变了"));
        assert_eq!(chain.next, "网关的设备变了。等它稳定，或重启路由器后再测。");
    }

    #[test]
    fn link_local_means_the_router_gave_no_address() {
        let mut r = healthy();
        r.nic_up = false;
        r.link_local = true;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "nic");
        assert_eq!(chain.hops[1].detail, "没有从路由器拿到地址");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "nic-address");
        assert_eq!(chain.next, book.check_first);
    }

    #[test]
    fn this_computer_filling_the_pipe_is_named_when_the_router_is_slow() {
        let mut r = healthy();
        r.gw_ms = 80;
        r.tx_bps = 2_500_000;
        r.rx_bps = 120_000;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "computer");
        assert_eq!(chain.hops[0].mark, "慢");
        assert!(chain.hops[0].detail.contains("发出 2.5 MB/s"));
        assert_eq!(
            chain.next,
            "这台电脑正在占带宽。先停掉正在下载的程序后再测。"
        );
    }

    #[test]
    fn noisy_wifi_is_slow_even_with_a_strong_signal() {
        let mut r = healthy();
        r.rssi = -60;
        r.noise = -70;
        r.noise_valid = true;
        let chain = judge(&r);
        assert_eq!(chain.hops[1].mark, "慢");
        assert!(chain.hops[1].detail.contains("噪声 -70"));
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "nic-air");
        assert_eq!(chain.next, book.check_first);
        assert!(book.look_at.iter().any(|item| item.contains("信道")));
    }

    #[test]
    fn arp_rows_count_two_macs_as_a_clash() {
        let rows = vec![
            ArpRow {
                ip: "192.168.1.1".into(),
                mac: "aa:bb:cc:dd:ee:01".into(),
            },
            ArpRow {
                ip: "192.168.1.1".into(),
                mac: "aa:bb:cc:dd:ee:02".into(),
            },
        ];
        assert_eq!(macs_for(&rows, "192.168.1.1").len(), 2);
        assert!(macs_for(&rows, "192.168.1.20").is_empty());
    }

    #[test]
    fn link_row_bytes_are_read() {
        let text = "\
Name  Mtu   Network     Address            Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
en0   1500  <Link#14>   aa:bb:cc:dd:ee:ff  10 0 1000 20 0 2000 0
en0   1500  192.168.1   192.168.1.20       10 0 50 20 0 80 0
";
        assert_eq!(parse_iface_bytes(text, "en0"), Some((1000, 2000)));
    }

    #[test]
    fn wifi_detail_keeps_band_and_channel_on_the_same_card() {
        let sample = serde_json::json!({
            "rssi": -55,
            "rssiValid": true,
            "noise": -92,
            "channel": 36,
            "band": "5GHz",
            "txRate": 866
        });
        let radio = radio_from_json(&sample).unwrap();
        assert_eq!(radio.band, "5 GHz");
        assert_eq!(radio.channel, 36);
        assert!(radio.rssi_valid);

        let mut r = healthy();
        r.band = radio.band;
        r.channel = radio.channel;
        r.noise = radio.noise;
        r.noise_valid = radio.noise_valid;
        r.tx_mbps = radio.tx_mbps;
        let chain = judge(&r);
        assert_eq!(chain.hops[1].mark, "通");
        assert_eq!(
            chain.hops[1].detail,
            "192.168.1.20 · 家里 · 5 GHz · 信道 36 · 噪声 -92 · 866 Mbps"
        );
        assert_eq!(chain.hops.len(), 6);

        let mut wired = healthy();
        wired.nic_wifi = false;
        wired.rssi_valid = false;
        wired.mbps = 1000;
        wired.band = "5 GHz".into();
        wired.channel = 36;
        wired.nic_label = "USB 10/100/1000 LAN".into();
        let chain = judge(&wired);
        assert!(!chain.hops[1].detail.contains("信道"));
        assert!(!chain.hops[1].detail.contains("GHz"));
        assert!(chain.hops[1].detail.contains("USB 10/100/1000 LAN"));
    }

    #[test]
    fn radio_json_keeps_channel_when_the_signal_is_missing() {
        let sample = serde_json::json!({
            "rssi": 0,
            "rssiValid": false,
            "channel": 6,
            "band": "2.4GHz",
            "txRate": 0
        });
        let radio = radio_from_json(&sample).unwrap();
        assert!(!radio.rssi_valid);
        assert_eq!(radio.band, "2.4 GHz");
        assert_eq!(radio.channel, 6);
        assert!(radio_from_json(&serde_json::json!({"rssi": 0, "rssiValid": false})).is_none());
        let airport = "     agrCtlRSSI: -48\n     agrCtlNoise: -90\n     channel: 149,80\n";
        assert_eq!(airport_channel(airport), 149);
    }

    #[test]
    fn a_listening_local_port_does_not_judge_the_proxy_when_the_system_proxy_is_off() {
        let mut r = healthy();
        r.proxy_on = false;
        r.local_proxy_port = 7897;
        r.clash_mode = "规则模式".into();
        let chain = judge(&r);
        assert_eq!(chain.hops[4].mark, "通");
        assert_eq!(chain.hops[4].number, 0);
        assert_eq!(
            chain.hops[4].detail,
            "系统代理关着，本机 7897 在听 · 规则模式"
        );
        assert_ne!(chain.problem_id, "proxy");
        assert!(chain.playbook.is_none());
        assert_eq!(chain.conclusion, "从这台电脑到外网是通的。");

        r.clash_mode.clear();
        let chain = judge(&r);
        assert_eq!(chain.hops[4].mark, "通");
        assert_eq!(chain.hops[4].detail, "系统代理关着，本机 7897 在听");

        r.dns_ok = false;
        r.dns_ms = 0;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "dns");
        assert_eq!(chain.hops[4].mark, "通");
        assert_eq!(chain.playbook.unwrap().id, "dns-down");
    }

    #[test]
    fn clash_mode_is_one_line_and_ignores_the_rest_of_the_body() {
        assert_eq!(
            clash_mode_from_body(r#"{"mode":"global","secret":"hidden","port":7890}"#).as_deref(),
            Some("全局模式")
        );
        assert_eq!(
            clash_mode_from_body(r#"{"mode":"direct"}"#).as_deref(),
            Some("直连模式")
        );
        assert!(clash_mode_from_body(r#"{"mode":"script"}"#).is_none());
        assert_eq!(LOCAL_PROXY_PORTS, &[7897, 7890, 7893, 1080, 1087, 20171]);
        let mut r = healthy();
        r.proxy_on = true;
        r.proxy_accepting = true;
        r.proxy_address = "127.0.0.1:7897".into();
        r.clash_mode = "全局模式".into();
        r.via_tested = true;
        r.via_ok = true;
        r.via_ms = 30;
        let chain = judge(&r);
        assert_eq!(chain.hops[4].mark, "通");
        assert_eq!(chain.hops[4].detail, "127.0.0.1:7897 · 全局模式");
        assert!(!chain.hops[4].detail.contains("secret"));
    }

    #[test]
    fn a_portal_redirect_is_a_fact_and_does_not_change_the_mark() {
        let mut r = healthy();
        r.https_kind = "ok".into();
        r.https_line = "www.baidu.com · 证书正常".into();
        r.redirect_count = 1;
        r.redirect_portal = true;
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.wan.https, "www.baidu.com · 证书正常 · 像门户认证");
        assert_eq!(chain.wan.https_kind, "ok");
        assert_eq!(chain.problem_id, "wan");
        let book = chain.playbook.unwrap();
        assert_eq!(book.id, "wan-portal");
        assert_eq!(book.look_at[0], "是不是门户认证");
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动关掉系统代理")));
        assert!(book
            .never_auto
            .iter()
            .any(|item| item.contains("不要自动改网络")));
        assert!(!chain.next.contains("关掉系统代理"));
        assert_eq!(chain.conclusion, "外网是通的。这一页在跳转。");

        r.nic_up = false;
        let chain = judge(&r);
        assert_eq!(chain.problem_id, "nic");
        assert_eq!(chain.conclusion, "出网断在网卡。");
        assert_eq!(chain.playbook.unwrap().id, "nic-down");
        assert_eq!(chain.wan.https, "www.baidu.com · 证书正常 · 像门户认证");
        assert_eq!(chain.hops[5].mark, "通");
    }

    #[test]
    fn many_redirects_stay_words_and_leave_the_mark_alone() {
        let mut r = healthy();
        r.https_kind = "ok".into();
        r.https_line = "www.baidu.com · 证书正常".into();
        r.redirect_count = 6;
        r.redirect_portal = false;
        let chain = judge(&r);
        assert_eq!(chain.hops[5].mark, "通");
        assert_eq!(chain.hops[5].number, 28);
        assert_eq!(chain.wan.https, "www.baidu.com · 证书正常 · 跳了 6 次");
        assert_eq!(chain.playbook.unwrap().id, "wan-portal");
        assert!(!chain.conclusion.contains("断"));

        r.redirect_count = 2;
        let chain = judge(&r);
        assert_eq!(chain.wan.https, "www.baidu.com · 证书正常");
        assert!(chain.playbook.is_none());
        assert_eq!(chain.conclusion, "从这台电脑到外网是通的。");
    }

    #[test]
    #[ignore]
    fn live_on_this_mac() {
        let chain = read_chain_now(&[], "");
        eprintln!("{}\n{}", chain.conclusion, chain.next);
        for hop in &chain.hops {
            eprintln!(
                "{} {} {} {}  {}",
                hop.name, hop.mark, hop.number, hop.unit, hop.detail
            );
        }
        eprintln!("nat {}", chain.wan.nat);
        eprintln!("https {}", chain.wan.https);
        for hop in &chain.wan.hops {
            eprintln!("  {} {}ms {} {}", hop.ttl, hop.ms, hop.note, hop.ip);
        }
        assert_eq!(chain.hops.len(), 6);
    }
}
