use argh::FromArgs;
use bytes::BytesMut;
use crossterm::{
    cursor,
    event::{self, KeyCode, KeyEvent},
    ExecutableCommand,
    terminal::{self, ClearType},
};
use moka::{future::Cache, Expiry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    io::self,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tokio::net::TcpStream;
use tui::{
    backend::CrosstermBackend,
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Terminal,
    widgets::{Block, Borders, List, ListItem, Row, Table, TableState},
};

#[derive(FromArgs, Debug)]
/// Simple Rust nDPIsrvd Client Example
struct Args {
    /// nDPIsrvd host(s) to connect to
    #[argh(option)]
    host: Vec<String>,
}

#[derive(Debug)]
enum ParseError {
    Protocol(),
    Json(),
    Schema(),
}

impl From<serde_json::Error> for ParseError {
    fn from(_: serde_json::Error) -> Self {
        ParseError::Json()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EventName {
    Invalid, New, End, Idle, Update, Analyse,
    Guessed, Detected,
    #[serde(rename = "detection-update")]
    DetectionUpdate,
    #[serde(rename = "not-detected")]
    NotDetected,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
enum State {
    Unknown, Info, Finished,
}

#[derive(Serialize, Deserialize, Debug)]
struct FlowEventNdpiFlowRisk {
    #[serde(rename = "risk")]
    risk: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FlowEventNdpi {
    #[serde(rename = "proto")]
    proto: String,
    #[serde(rename = "flow_risk")]
    risks: Option<HashMap<String, FlowEventNdpiFlowRisk>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct FlowEvent {
    #[serde(rename = "flow_event_name")]
    name: EventName,
    #[serde(rename = "flow_id")]
    id: u64,
    #[serde(rename = "alias")]
    alias: String,
    #[serde(rename = "source")]
    source: String,
    #[serde(rename = "thread_id")]
    thread_id: u64,
    #[serde(rename = "flow_state")]
    state: State,
    #[serde(rename = "flow_first_seen")]
    first_seen: u64,
    #[serde(rename = "flow_src_last_pkt_time")]
    src_last_pkt_time: u64,
    #[serde(rename = "flow_dst_last_pkt_time")]
    dst_last_pkt_time: u64,
    #[serde(rename = "flow_idle_time")]
    idle_time: u64,
    #[serde(rename = "flow_src_packets_processed")]
    src_packets_processed: u64,
    #[serde(rename = "flow_dst_packets_processed")]
    dst_packets_processed: u64,
    #[serde(rename = "flow_src_tot_l4_payload_len")]
    src_tot_l4_payload_len: u64,
    #[serde(rename = "flow_dst_tot_l4_payload_len")]
    dst_tot_l4_payload_len: u64,
    #[serde(rename = "l3_proto")]
    l3_proto: String,
    #[serde(rename = "l4_proto")]
    l4_proto: String,
    #[serde(rename = "ndpi")]
    ndpi: Option<FlowEventNdpi>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PacketEvent {
    pkt_datalink: u16,
    pkt_caplen: u64,
    pkt_len: u64,
    pkt_l4_len: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DaemonEventStatus {
    #[serde(rename = "alias")]
    alias: String,
    #[serde(rename = "source")]
    source: String,
    #[serde(rename = "thread_id")]
    thread_id: u64,
    #[serde(rename = "packets-captured")]
    packets_captured: u64,
    #[serde(rename = "packets-processed")]
    packets_processed: u64,
    #[serde(rename = "total-skipped-flows")]
    total_skipped_flows: u64,
    #[serde(rename = "total-l4-payload-len")]
    total_l4_payload_len: u64,
    #[serde(rename = "total-not-detected-flows")]
    total_not_detected_flows: u64,
    #[serde(rename = "total-guessed-flows")]
    total_guessed_flows: u64,
    #[serde(rename = "total-detected-flows")]
    total_detected_flows: u64,
    #[serde(rename = "total-detection-updates")]
    total_detection_updates: u64,
    #[serde(rename = "total-updates")]
    total_updates: u64,
    #[serde(rename = "current-active-flows")]
    current_active_flows: u64,
    #[serde(rename = "total-active-flows")]
    total_active_flows: u64,
    #[serde(rename = "total-idle-flows")]
    total_idle_flows: u64,
    #[serde(rename = "total-compressions")]
    total_compressions: u64,
    #[serde(rename = "total-compression-diff")]
    total_compression_diff: u64,
    #[serde(rename = "current-compression-diff")]
    current_compression_diff: u64,
    #[serde(rename = "global-alloc-bytes")]
    global_alloc_bytes: u64,
    #[serde(rename = "global-alloc-count")]
    global_alloc_count: u64,
    #[serde(rename = "global-free-bytes")]
    global_free_bytes: u64,
    #[serde(rename = "global-free-count")]
    global_free_count: u64,
    #[serde(rename = "total-events-serialized")]
    total_events_serialized: u64,
}

#[derive(Debug)]
enum EventType {
    Flow(FlowEvent),
    Packet(PacketEvent),
    DaemonStatus(DaemonEventStatus),
    Other(),
}

#[derive(Default)]
struct Stats {
    ui_updates: u64,
    flow_count: u64,
    parse_errors: u64,
    events: u64,
    flow_events: u64,
    packet_events: u64,
    daemon_events: u64,
    packet_events_total_caplen: u64,
    packet_events_total_len: u64,
    packet_events_total_l4_len: u64,
    packets_captured: u64,
    packets_processed: u64,
    flows_total_skipped: u64,
    flows_total_l4_payload_len: u64,
    flows_total_not_detected: u64,
    flows_total_guessed: u64,
    flows_current_active: u64,
    flows_total_compressions: u64,
    flows_total_compression_diff: u64,
    flows_current_compression_diff: u64,
    global_alloc_bytes: u64,
    global_alloc_count: u64,
    global_free_bytes: u64,
    global_free_count: u64,
    total_events_serialized: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowExpiration {
    IdleTime(u64),
}

struct FlowExpiry;

#[derive(Clone, Eq, Default, Debug)]
struct FlowKey {
    id: u64,
    alias: String,
    source: String,
    thread_id: u64,
}

#[derive(Clone, Debug)]
struct FlowValue {
    state: State,
    total_src_packets: u64,
    total_dst_packets: u64,
    total_src_bytes: u64,
    total_dst_bytes: u64,
    first_seen: std::time::SystemTime,
    last_seen: std::time::SystemTime,
    timeout_in: std::time::SystemTime,
    risks: usize,
    proto: String,
    app_proto: String,
}

#[derive(Clone, Eq, Default, Debug)]
struct DaemonKey {
    alias: String,
    source: String,
    thread_id: u64,
}

impl Default for State {
    fn default() -> State {
        State::Unknown
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Unknown => write!(f, "N/A"),
            State::Info => write!(f, "Info"),
            State::Finished => write!(f, "Finished"),
        }
    }
}

impl FlowExpiration {
    fn as_duration(&self) -> Option<Duration> {
        match self {
            FlowExpiration::IdleTime(value) => Some(Duration::from_micros(*value)),
        }
    }
}

impl fmt::Display for FlowExpiration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_duration() {
            Some(duration) => {
                let secs = duration.as_secs();
                write!(f, "{} s", secs)
            }
            None => write!(f, "N/A"),
        }
    }
}

impl Expiry<FlowKey, (FlowExpiration, FlowValue)> for FlowExpiry {
    fn expire_after_create(
        &self,
        _key: &FlowKey,
        value: &(FlowExpiration, FlowValue),
        _current_time: Instant,
    ) -> Option<Duration> {
        value.0.as_duration()
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.alias.hash(state);
        self.source.hash(state);
        self.thread_id.hash(state);
    }
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id &&
        self.alias == other.alias &&
        self.source == other.source &&
        self.thread_id == other.thread_id
    }
}

impl Hash for DaemonKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.alias.hash(state);
        self.source.hash(state);
        self.thread_id.hash(state);
    }
}

impl PartialEq for DaemonKey {
    fn eq(&self, other: &Self) -> bool {
        self.alias == other.alias &&
        self.source == other.source &&
        self.thread_id == other.thread_id
    }
}

#[tokio::main]
async fn main() {
    let args: Args = argh::from_env();
    if args.host.len() == 0 {
        eprintln!("At least one --host required");
        return;
    }

    let mut connections: Vec<TcpStream> = Vec::new();
    for host in args.host {
        match TcpStream::connect(host.clone()).await {
            Ok(stream) => {
                connections.push(stream);
            }
            Err(e) => {
                eprintln!("Fehler bei Verbindung zu {}: {}", host, e);
            }
        }
    }

    if let Err(e) = terminal::enable_raw_mode() {
        eprintln!("Could not enable terminal raw mode: {}", e);
        return;
    }
    let mut stdout = io::stdout();
    if let Err(e) = stdout.execute(terminal::Clear(ClearType::All)) {
        eprintln!("Could not clear your terminal: {}", e);
        return;
    }
    if let Err(e) = stdout.execute(cursor::Hide) {
        eprintln!("Could not hide your cursor: {}", e);
        return;
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend);

    let (tx, mut rx): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel(1024);
    let data = Arc::new(Mutex::new(Stats::default()));
    let data_tx = Arc::clone(&data);
    let data_rx = Arc::clone(&data);
    let flow_cache: Arc<Cache<FlowKey, (FlowExpiration, FlowValue)>> = Arc::new(Cache::builder()
                                                                       .expire_after(FlowExpiry)
                                                                       .build());
    let flow_cache_rx = Arc::clone(&flow_cache);
    let daemon_cache: Arc<Cache<DaemonKey, DaemonEventStatus>> = Arc::new(Cache::builder()
                                                            .time_to_live(Duration::from_secs(1800))
                                                            .build());

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match parse_json(&msg) {
                Ok(message) => {
                    let mut data_lock = data_tx.lock().await;
                    data_lock.events += 1;
                    update_stats(&message, &mut data_lock, &flow_cache, &daemon_cache).await;
                }
                Err(_message) => {
                    let mut data_lock = data_tx.lock().await;
                    data_lock.parse_errors += 1;
                }
            }
        }
    });

    for mut stream in connections {
        let cloned_tx = tx.clone();
        tokio::spawn(async move {
            let mut buffer = BytesMut::with_capacity(33792usize);

            loop {
                let n = match stream.read_buf(&mut buffer).await {
                    Ok(len) => len,
                    Err(_) => {
                        continue; // Versuche es erneut, wenn ein Fehler auftritt
                    }
                };
                if n == 0 {
                    break;
                }

                while let Some(message) = parse_message(&mut buffer) {
                    match cloned_tx.send(message).await {
                        Ok(_) => (),
                        Err(_) => return
                    }
                }
            }
        });
    }

    let mut table_state = TableState::default();
    let mut old_selected: Option<FlowKey> = None;

    loop {
        let flows: Vec<(FlowKey, (FlowExpiration, FlowValue))> = flow_cache_rx.iter().map(|(k, v)| (k.as_ref().clone(), v.clone()))
                                                                     .take(128)
                                                                     .collect();
        let mut table_selected = match table_state.selected() {
            Some(mut table_index) => {
                if table_index >= flows.len() {
                    flows.len().saturating_sub(1)
                } else {
                    if let Some(ref old_flow_key_selected) = old_selected {
                        if let Some(old_index) = flows.iter().position(|x| x.0 == *old_flow_key_selected) {
                            if old_index != table_index {
                                table_index = old_index;
                            }
                        } else {
                            old_selected = Some(flows.get(table_index).unwrap().0.clone());
                        }
                    }
                    table_index
                }
            }
            None => 0,
        };

        match read_keypress() {
            Some(KeyCode::Esc) => break,
            Some(KeyCode::Char('q')) => break,
            Some(KeyCode::Up) => {
                table_selected = match table_selected {
                    i if i == 0 => flows.len().saturating_sub(1),
                    i => i - 1,
                };
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(KeyCode::Down) => {
                table_selected = match table_selected {
                    i if i >= flows.len().saturating_sub(1) => 0,
                    i => i + 1,
                };
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(KeyCode::PageUp) => {
                table_selected = match table_selected {
                    i if i == 0 => flows.len().saturating_sub(1),
                    i if i < 25 => 0,
                    i => i - 25,
                };
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(KeyCode::PageDown) => {
                table_selected = match table_selected {
                    i if i >= flows.len().saturating_sub(1) => 0,
                    i if i >= flows.len().saturating_sub(25) => flows.len().saturating_sub(1),
                    i => i + 25,
                };
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(KeyCode::Home) => {
                table_selected = 0;
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(KeyCode::End) => {
                table_selected = match table_selected {
                    _ => flows.len().saturating_sub(1),
                };
                if let Some(new_selected) = flows.get(table_selected) {
                    old_selected = Some(new_selected.0.clone());
                }
            },
            Some(_) => (),
            None => ()
        };

        let mut data_lock = data_rx.lock().await;
        data_lock.ui_updates += 1;
        draw_ui(terminal.as_mut().unwrap(), &mut table_state, table_selected, &data_lock, &flows);
    }

    if let Err(e) = terminal.unwrap().backend_mut().execute(cursor::Show) {
        eprintln!("Could not show your cursor: {}", e);
        return;
    }
    let mut stdout = io::stdout();
    if let Err(e) = stdout.execute(terminal::Clear(ClearType::All)) {
        eprintln!("Could not clear your terminal: {}", e);
        return;
    }
    if let Err(e) = terminal::disable_raw_mode() {
        eprintln!("Could not disable raw mode: {}", e);
        return;
    }
    println!("\nDone.");
}

fn read_keypress() -> Option<KeyCode> {
    if event::poll(Duration::from_millis(1000)).unwrap() {
        if let event::Event::Key(KeyEvent { code, .. }) = event::read().unwrap() {
            return Some(code);
        }
    }

    None
}

fn parse_message(buffer: &mut BytesMut) -> Option<String> {
    if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
        let message = buffer.split_to(pos + 1);
        return Some(String::from_utf8_lossy(&message).to_string());
    }

    None
}

fn parse_json(data: &str) -> Result<EventType, ParseError> {
    let first_non_digit = data.find(|c: char| !c.is_ascii_digit()).unwrap_or(0);
    let length_str = &data[0..first_non_digit];
    let length: usize = length_str.parse().unwrap_or(0);
    if length == 0 {
        return Err(ParseError::Protocol());
    }

    let json_str = &data[first_non_digit..first_non_digit + length];
    let value: Value = serde_json::from_str(json_str).map_err(|_| ParseError::Json()).unwrap();
    if value.get("flow_event_name").is_some() {
        let flow_event: FlowEvent = serde_json::from_value(value)?;
        return Ok(EventType::Flow(flow_event));
    } else if value.get("packet_event_name").is_some() {
        let packet_event: PacketEvent = serde_json::from_value(value)?;
        return Ok(EventType::Packet(packet_event));
    } else if value.get("daemon_event_name").is_some() {
        if value.get("daemon_event_name").unwrap() == "status" ||
           value.get("daemon_event_name").unwrap() == "shutdown"
        {
            let daemon_status_event: DaemonEventStatus = serde_json::from_value(value)?;
            return Ok(EventType::DaemonStatus(daemon_status_event));
        }
        return Ok(EventType::Other());
    } else if value.get("error_event_name").is_some() {
        return Ok(EventType::Other());
    }

    Err(ParseError::Schema())
}

async fn update_stats(event: &EventType, stats: &mut MutexGuard<'_, Stats>, cache: &Cache<FlowKey, (FlowExpiration, FlowValue)>, daemon_cache: &Cache<DaemonKey, DaemonEventStatus>) {
    match &event {
        EventType::Flow(flow_event) => {
            stats.flow_events += 1;
            stats.flow_count = cache.entry_count();
            let key = FlowKey { id: flow_event.id, alias: flow_event.alias.to_string(),
                                source: flow_event.source.to_string(), thread_id: flow_event.thread_id };

            if flow_event.name == EventName::End ||
               flow_event.name == EventName::Idle
            {
                cache.remove(&key).await;
                return;
            }

            let first_seen_seconds = flow_event.first_seen / 1_000_000;
            let first_seen_nanos = (flow_event.first_seen % 1_000_000) * 1_000;
            let first_seen_epoch = std::time::Duration::new(first_seen_seconds, first_seen_nanos as u32);
            let first_seen_system = UNIX_EPOCH + first_seen_epoch;

            let last_seen = std::cmp::max(flow_event.src_last_pkt_time,
                                          flow_event.dst_last_pkt_time);
            let last_seen_seconds = last_seen / 1_000_000;
            let last_seen_nanos = (last_seen % 1_000_000) * 1_000;
            let last_seen_epoch = std::time::Duration::new(last_seen_seconds, last_seen_nanos as u32);
            let last_seen_system = UNIX_EPOCH + last_seen_epoch;

            let timeout_seconds = (last_seen + flow_event.idle_time) / 1_000_000;
            let timeout_nanos = ((last_seen + flow_event.idle_time) % 1_000_000) * 1_000; 
            let timeout_epoch = std::time::Duration::new(timeout_seconds, timeout_nanos as u32);
            let timeout_system = UNIX_EPOCH + timeout_epoch;

            let risks = match &flow_event.ndpi {
                None => 0,
                Some(ndpi) => match &ndpi.risks {
                    None => 0,
                    Some(risks) => risks.len(),
                },
            };

            let app_proto = match &flow_event.ndpi {
                None => "-",
                Some(ndpi) => &ndpi.proto,
            };

            let value = FlowValue {
                state: flow_event.state,
                total_src_packets: flow_event.src_packets_processed,
                total_dst_packets: flow_event.dst_packets_processed,
                total_src_bytes: flow_event.src_tot_l4_payload_len,
                total_dst_bytes: flow_event.dst_tot_l4_payload_len,
                first_seen: first_seen_system,
                last_seen: last_seen_system,
                timeout_in: timeout_system,
                risks: risks,
                proto: flow_event.l3_proto.to_string() + "/" + &flow_event.l4_proto,
                app_proto: app_proto.to_string(),
            };
            cache.insert(key, (FlowExpiration::IdleTime(flow_event.idle_time), value)).await;
        }
        EventType::Packet(packet_event) => {
            stats.packet_events += 1;
            stats.packet_events_total_caplen += packet_event.pkt_caplen;
            stats.packet_events_total_len += packet_event.pkt_len;
            stats.packet_events_total_l4_len += packet_event.pkt_l4_len;
        }
        EventType::DaemonStatus(daemon_status_event) => {
            let key = DaemonKey { alias: daemon_status_event.alias.to_string(),
                                  source: daemon_status_event.source.to_string(),
                                  thread_id: daemon_status_event.thread_id };
            stats.daemon_events += 1;
            daemon_cache.insert(key, daemon_status_event.clone()).await;

            stats.packets_captured = 0;
            stats.packets_processed = 0;
            stats.flows_total_skipped = 0;
            stats.flows_total_l4_payload_len = 0;
            stats.flows_total_not_detected = 0;
            stats.flows_total_guessed = 0;
            stats.flows_current_active = 0;
            stats.flows_total_compressions = 0;
            stats.flows_total_compression_diff = 0;
            stats.flows_current_compression_diff = 0;
            stats.global_alloc_bytes = 0;
            stats.global_alloc_count = 0;
            stats.global_free_bytes = 0;
            stats.global_free_count = 0;
            stats.total_events_serialized = 0;
            let daemons: Vec<DaemonEventStatus> = daemon_cache.iter().map(|(_, v)| (v.clone())).collect();
            for daemon in daemons {
                stats.packets_captured += daemon.packets_captured;
                stats.packets_processed += daemon.packets_processed;
                stats.flows_total_skipped += daemon.total_skipped_flows;
                stats.flows_total_l4_payload_len += daemon.total_l4_payload_len;
                stats.flows_total_not_detected += daemon.total_not_detected_flows;
                stats.flows_total_guessed += daemon.total_guessed_flows;
                stats.flows_current_active += daemon.current_active_flows;
                stats.flows_total_compressions += daemon.total_compressions;
                stats.flows_total_compression_diff += daemon.total_compression_diff;
                stats.flows_current_compression_diff += daemon.current_compression_diff;
                stats.global_alloc_bytes += daemon.global_alloc_bytes;
                stats.global_alloc_count += daemon.global_alloc_count;
                stats.global_free_bytes += daemon.global_free_bytes;
                stats.global_free_count += daemon.global_free_count;
                stats.total_events_serialized += daemon.total_events_serialized;
            }
        }
        EventType::Other() => {}
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{} kB", bytes / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn draw_ui<B: tui::backend::Backend>(terminal: &mut Terminal<B>, table_state: &mut TableState, table_selected: usize, data: &MutexGuard<Stats>, flows: &Vec<(FlowKey, (FlowExpiration, FlowValue))>) {
    let general_items = vec![
        ListItem::new("TUI Updates..: ".to_owned() + &data.ui_updates.to_string()),
        ListItem::new("Flows Cached.: ".to_owned() + &data.flow_count.to_string()),
        ListItem::new("Total Events.: ".to_owned() + &data.events.to_string()),
        ListItem::new("Parse Errors.: ".to_owned() + &data.parse_errors.to_string()),
        ListItem::new("Flow Events..: ".to_owned() + &data.flow_events.to_string()),
    ];
    let packet_items = vec![
        ListItem::new("Total Events........: ".to_owned() + &data.packet_events.to_string()),
        ListItem::new("Total Capture Length: ".to_owned() + &format_bytes(data.packet_events_total_caplen)),
        ListItem::new("Total Length........: ".to_owned() + &format_bytes(data.packet_events_total_len)),
        ListItem::new("Total L4 Length.....: ".to_owned() + &format_bytes(data.packet_events_total_l4_len)),
    ];
    let daemon_items = vec![
        ListItem::new("Total Events.............: ".to_owned() + &data.daemon_events.to_string()),
        ListItem::new("Total Packets Captured...: ".to_owned() + &data.packets_captured.to_string()),
        ListItem::new("Total Packets Processed..: ".to_owned() + &data.packets_processed.to_string()),
        ListItem::new("Total Flows Skipped......: ".to_owned() + &data.flows_total_skipped.to_string()),
        ListItem::new("Total Flows Not-Detected.: ".to_owned() + &data.flows_total_not_detected.to_string()),
        ListItem::new("Total Compressions/Memory: ".to_owned() + &data.flows_total_compressions.to_string()
                      + " / " + &format_bytes(data.flows_total_compression_diff) + " deflate"),
        ListItem::new("Total Memory in Use......: ".to_owned() + &format_bytes(data.global_alloc_bytes - data.global_free_bytes)
                      + " (" + &format_bytes(data.flows_current_compression_diff) + " deflate)"),
        ListItem::new("Total Events Serialized..: ".to_owned() + &data.total_events_serialized.to_string()),
        ListItem::new("Current Flows Active.....: ".to_owned() + &data.flows_current_active.to_string()),
    ];
    let table_rows: Vec<Row> = flows
        .into_iter()
        .map(|(key, (_exp, val))| {
            let first_seen_display = match val.first_seen.elapsed() {
                Ok(elapsed) => {
                    match elapsed.as_secs() {
                        t if t > (3_600 * 24) => format!("{} d ago", t / (3_600 * 24)),
                        t if t > 3_600 => format!("{} h ago", t / 3_600),
                        t if t > 60 => format!("{} min ago", t / 60),
                        t if t > 0 => format!("{} s ago", t),
                        t if t == 0 => "< 1 s ago".to_string(),
                        t => format!("INVALID: {}", t),
                    }
                }
                Err(err) => format!("ERROR: {}", err)
            };

            let last_seen_display = match val.last_seen.elapsed() {
                Ok(elapsed) => {
                    match elapsed.as_secs() {
                        t if t > (3_600 * 24) => format!("{} d ago", t / (3_600 * 24)),
                        t if t > 3_600 => format!("{} h ago", t / 3_600),
                        t if t > 60 => format!("{} min ago", t / 60),
                        t if t > 0 => format!("{} s ago", t),
                        t if t == 0 => "< 1 s ago".to_string(),
                        t => format!("INVALID: {}", t),
                    }
                }
                Err(_err) => "ERROR".to_string()
            };

            let timeout_display = match val.timeout_in.duration_since(SystemTime::now()) {
                Ok(elapsed) => {
                    match elapsed.as_secs() {
                        t if t > (3_600 * 24) => format!("in {} d", t / (3_600 * 24)),
                        t if t > 3_600 => format!("in {} h", t / 3_600),
                        t if t > 60 => format!("in {} min", t / 60),
                        t if t > 0 => format!("in {} s", t),
                        t if t == 0 => "in < 1 s".to_string(),
                        t => format!("INVALID: {}", t),
                    }
                }
                Err(_err) => "EXPIRED".to_string()
            };

            Row::new(vec![
                key.id.to_string(),
                val.state.to_string(),
                first_seen_display,
                last_seen_display,
                timeout_display,
                (val.total_src_packets + val.total_dst_packets).to_string(),
                format_bytes(val.total_src_bytes + val.total_dst_bytes),
                val.risks.to_string(),
                val.proto.to_string(),
                val.app_proto.to_string(),
            ])
        })
        .collect();

    terminal.draw(|f| {
        let size = f.size();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(11),
                    Constraint::Percentage(100),
                ].as_ref()
            )
            .split(size);

        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Percentage(25),
                    Constraint::Percentage(30),
                    Constraint::Percentage(55),
                ].as_ref()
            )
            .split(chunks[0]);

        let table_selected_abs = match table_selected {
            _ if flows.len() == 0 => 0,
            i => i + 1,
        };
        let table = Table::new(table_rows)
            .header(Row::new(vec!["Flow ID", "State", "First Seen", "Last Seen", "Timeout", "Total Packets", "Total Bytes", "Risks", "L3/L4", "L7"])
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                .block(Block::default().title("Flow Table (selected: ".to_string() +
                                              &table_selected_abs.to_string() +
                                              "): " +
                                              &flows.len().to_string() +
                                              " item(s)").borders(Borders::ALL))
                .highlight_style(Style::default().bg(Color::Blue))
                .widths(&[
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(10),
                    Constraint::Length(13),
                    Constraint::Length(12),
                    Constraint::Length(6),
                    Constraint::Length(12),
                    Constraint::Length(15),
                ]);

        let general_list = List::new(general_items)
            .block(Block::default().title("General").borders(Borders::ALL));
        let packet_list = List::new(packet_items)
            .block(Block::default().title("Packet Events").borders(Borders::ALL));
        let daemon_list = List::new(daemon_items)
            .block(Block::default().title("Daemon Events").borders(Borders::ALL));

        table_state.select(Some(table_selected));
        f.render_widget(general_list, top_chunks[0]);
        f.render_widget(packet_list, top_chunks[1]);
        f.render_widget(daemon_list, top_chunks[2]);
        f.render_stateful_widget(table, chunks[1], table_state);
    }).unwrap();
}
