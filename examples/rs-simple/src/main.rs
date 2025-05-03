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
    hash::{Hash, Hasher},
    io::self,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tokio::net::TcpStream;
use tui::{
    backend::CrosstermBackend,
    layout::{Layout, Constraint, Direction},
    style::{Style, Color},
    Terminal,
    widgets::{Block, Borders, List, ListItem},
};

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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum EventName {
    Invalid, New, End, Idle, Update, Analyse,
    Guessed, Detected,
    #[serde(rename = "detection-update")]
    DetectionUpdate,
    #[serde(rename = "not-detected")]
    NotDetected,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum State {
    Info, Finished,
}

#[derive(Serialize, Deserialize, Debug)]
struct FlowEvent {
    #[serde(rename = "flow_event_name")]
    name: EventName,
    #[serde(rename = "flow_id")]
    id: u64,
    #[serde(rename = "flow_state")]
    state: State,
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
}

#[derive(Serialize, Deserialize, Debug)]
struct PacketEvent {
    pkt_datalink: u16,
    pkt_caplen: u64,
    pkt_len: u64,
    pkt_l4_len: u64,
}

#[derive(Debug)]
enum EventType {
    Flow(FlowEvent),
    Packet(PacketEvent),
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
    total_caplen: u64,
    total_len: u64,
    total_l4_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expiration {
    FlowIdleTime(u64),
}

struct FlowExpiry;

#[derive(Eq, Default, Debug)]
struct FlowKey {
    id: u64,
}

#[derive(Clone, Default, Debug)]
struct FlowValue {
}

impl Expiration {
    fn as_duration(&self) -> Option<Duration> {
        match self {
            Expiration::FlowIdleTime(value) => Some(Duration::from_micros(*value)),
        }
    }
}

impl Expiry<FlowKey, (Expiration, FlowValue)> for FlowExpiry {
    fn expire_after_create(
        &self,
        _key: &FlowKey,
        value: &(Expiration, FlowValue),
        _current_time: Instant,
    ) -> Option<Duration> {
        value.0.as_duration()
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[tokio::main]
async fn main() {
    let server_address = "127.0.0.1:7000";

    let mut stream = match TcpStream::connect(server_address).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Connection to {} failed: {}", server_address, e);
            return;
        }
    };
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

    let mut buffer = BytesMut::with_capacity(33792usize);
    let (tx, mut rx): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel(1024);
    let data = Arc::new(Mutex::new(Stats::default()));
    let data_tx = Arc::clone(&data);
    let data_rx = Arc::clone(&data);

    tokio::spawn(async move {
        let expiry = FlowExpiry;
        let flow_cache: Cache<FlowKey, (Expiration, FlowValue)> = Cache::builder()
            .expire_after(expiry)
            .build();

        while let Some(msg) = rx.recv().await {
            match parse_json(&msg) {
                Ok(message) => {
                    let mut data_lock = data_tx.lock().await;
                    data_lock.events += 1;
                    update_stats(&message, &mut data_lock, &flow_cache).await;
                }
                Err(_message) => {
                    let mut data_lock = data_tx.lock().await;
                    data_lock.parse_errors += 1;
                }
            }
        }
    });
    tokio::spawn(async move {
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
                match tx.send(message).await {
                    Ok(_) => (),
                    Err(_) => return
                }
            }
        }
    });

    loop {
        match read_keypress() {
            Some(KeyCode::Esc) => break,
            Some(KeyCode::Char('q')) => break,
            Some(_) => (),
            None => ()
        };
        let mut data_lock = data_rx.lock().await;
        data_lock.ui_updates += 1;
        draw_ui(terminal.as_mut().unwrap(), &data_lock);
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
    if event::poll(Duration::from_millis(500)).unwrap() {
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
    } else if value.get("daemon_event_name").is_some() ||
              value.get("error_event_name").is_some() {
        return Ok(EventType::Other());
    }

    Err(ParseError::Schema())
}

async fn update_stats(event: &EventType, stats: &mut MutexGuard<'_, Stats>, cache: &Cache<FlowKey, (Expiration, FlowValue)>) {
    match &event {
        EventType::Flow(flow_event) => {
            stats.flow_events += 1;
            stats.flow_count = cache.entry_count();

            let key = FlowKey { id: flow_event.id };
            let value = FlowValue {};
            cache.insert(key, (Expiration::FlowIdleTime(flow_event.idle_time), value)).await;
        }
        EventType::Packet(packet_event) => {
            stats.packet_events += 1;
            stats.total_caplen += packet_event.pkt_caplen;
            stats.total_len += packet_event.pkt_len;
            stats.total_l4_len += packet_event.pkt_l4_len;
        }
        EventType::Other() => {}
    }
}

fn draw_ui<B: tui::backend::Backend>(terminal: &mut Terminal<B>, data: &MutexGuard<Stats>) {
    let general_items = vec![
        ListItem::new("TUI Updates..: ".to_owned() + &data.ui_updates.to_string()),
        ListItem::new("Flow Count...: ".to_owned() + &data.flow_count.to_string()),
        ListItem::new("Total Events.: ".to_owned() + &data.events.to_string()),
        ListItem::new("Parse Errors.: ".to_owned() + &data.parse_errors.to_string()),
        ListItem::new("Flow Events..: ".to_owned() + &data.flow_events.to_string()),
        ListItem::new("Packet Events: ".to_owned() + &data.packet_events.to_string()),
    ];
    let packet_items = vec![
        ListItem::new("Total Capture Length: ".to_owned() + &data.total_caplen.to_string()),
        ListItem::new("Total Length........: ".to_owned() + &data.total_len.to_string()),
        ListItem::new("Total L4 Length.....: ".to_owned() + &data.total_l4_len.to_string()),
    ];

    terminal.draw(|f| {
        let size = f.size();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(20),
                    Constraint::Percentage(50),
                ].as_ref()
            )
            .split(size);

        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ].as_ref()
            )
            .split(chunks[0]);

        let right_block = Block::default()
            .title("Unused Bottom Panel")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Black).bg(Color::Green));

        let general_list = List::new(general_items)
            .block(Block::default().title("General").borders(Borders::ALL));
        let packet_list = List::new(packet_items)
            .block(Block::default().title("Packet").borders(Borders::ALL));

        f.render_widget(general_list, top_chunks[0]);
        f.render_widget(packet_list, top_chunks[1]);
        f.render_widget(right_block, chunks[1]);
    }).unwrap();
}
