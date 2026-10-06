use std::{
    io,
    time::{Duration, Instant},
    collections::VecDeque,
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Axis, Block, Borders, Chart, Dataset, GraphType,
        List, ListItem, Paragraph, Sparkline, Wrap,
    },
    Frame, Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use serde::Deserialize;

// --- Data structures ---------------------------------------------------------

const HISTORY_LEN: usize = 60;   // Keep last 60 data points

#[derive(Debug, Default, Clone, Deserialize)]
struct Metrics {
    cpu_usage_percent:        f64,
    avg_wait_ns:              u64,
    tasks_in_queue:           u32,
    context_switches_per_sec: u32,
    io_wait_percent:          f64,
    active_scheduler:         String,
    timestamp:                String,
}

struct AppState {
    cpu_history:     VecDeque<(f64, f64)>,  // (time_offset, cpu%)
    wait_history:    VecDeque<u64>,          // avg_wait_ns
    queue_history:   VecDeque<u64>,          // task queue depth
    current:         Metrics,
    log_entries:     VecDeque<String>,
    start_time:      Instant,
    active_sched:    String,
    last_ai_thought: String,
    frame_count:     u64,
}

impl AppState {
    fn new() -> Self {
        Self {
            cpu_history:     VecDeque::with_capacity(HISTORY_LEN),
            wait_history:    VecDeque::with_capacity(HISTORY_LEN),
            queue_history:   VecDeque::with_capacity(HISTORY_LEN),
            current:         Metrics::default(),
            log_entries:     VecDeque::with_capacity(20),
            start_time:      Instant::now(),
            active_sched:    "cfs (default)".into(),
            last_ai_thought: "Waiting for first AI decision...".into(),
            frame_count:     0,
        }
    }

    fn push_metrics(&mut self, m: Metrics) {
        let elapsed = self.start_time.elapsed().as_secs_f64();

        // Maintain rolling window
        if self.cpu_history.len() >= HISTORY_LEN {
            self.cpu_history.pop_front();
            self.wait_history.pop_front();
            self.queue_history.pop_front();
        }

        self.cpu_history.push_back((elapsed, m.cpu_usage_percent));
        self.wait_history.push_back(m.avg_wait_ns / 1_000_000); // convert to ms
        self.queue_history.push_back(m.tasks_in_queue as u64);

        if m.active_scheduler != self.active_sched {
            self.add_log(format!(
                " Scheduler changed: {} -> {}",
                self.active_sched, m.active_scheduler
            ));
            self.active_sched = m.active_scheduler.clone();
        }

        self.current = m;
        self.frame_count += 1;
    }

    fn add_log(&mut self, msg: String) {
        if self.log_entries.len() >= 20 {
            self.log_entries.pop_front();
        }
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log_entries.push_back(format!("[{ts}] {msg}"));
    }
}

// --- UI Drawing --------------------------------------------------------------

fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    // Main layout: header + body + footer
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(10),     // Body
            Constraint::Length(3),   // Footer
        ])
        .split(size);

    draw_header(f, root[0], state);
    draw_body(f, root[1], state);
    draw_footer(f, root[2], state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let elapsed = state.start_time.elapsed().as_secs();
    let (h, m, s) = (elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);

    let sched_color = match state.active_sched.as_str() {
        s if s.contains("latency")    => Color::Green,
        s if s.contains("fifo")       => Color::Yellow,
        s if s.contains("throughput") => Color::Cyan,
        _                             => Color::Gray,
    };

    let title = Line::from(vec![
        Span::styled(" SchedAI ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("| "),
        Span::raw("Active: "),
        Span::styled(&state.active_sched, Style::default().fg(sched_color).add_modifier(Modifier::BOLD)),
        Span::raw(format!("  |  Uptime: {:02}:{:02}:{:02}", h, m, s)),
        Span::raw(format!("  |  Frames: {}", state.frame_count)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title("AI-Driven Linux CPU Scheduler");

    let para = Paragraph::new(title).block(block);
    f.render_widget(para, area);
}

fn draw_body(f: &mut Frame, area: Rect, state: &AppState) {
    // Body: left (charts) | right (stats + log)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    draw_charts(f, cols[0], state);
    draw_sidebar(f, cols[1], state);
}

fn draw_charts(f: &mut Frame, area: Rect, state: &AppState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    // CPU Usage Line Chart
    let cpu_data: Vec<(f64, f64)> = state.cpu_history.iter().cloned().collect();
    let datasets = vec![
        Dataset::default()
            .name("CPU %")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Cyan))
            .data(&cpu_data),
    ];

    let x_range = if let (Some(first), Some(last)) = (cpu_data.first(), cpu_data.last()) {
        [first.0, last.0.max(first.0 + 1.0)]
    } else {
        [0.0, 60.0]
    };

    let cpu_chart = Chart::new(datasets)
        .block(Block::default()
            .title(format!("CPU Usage: {:.1}%", state.current.cpu_usage_percent))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)))
        .x_axis(Axis::default()
            .bounds(x_range)
            .style(Style::default().fg(Color::DarkGray)))
        .y_axis(Axis::default()
            .bounds([0.0, 100.0])
            .labels(vec![
                Span::raw("0%"),
                Span::raw("50%"),
                Span::raw("100%"),
            ])
            .style(Style::default().fg(Color::DarkGray)));
    f.render_widget(cpu_chart, rows[0]);

    // Wait Time Sparkline
    let wait_data: Vec<u64> = state.wait_history.iter().cloned().collect();
    let wait_spark = Sparkline::default()
        .block(Block::default()
            .title(format!("Avg Task Wait: {:.1}ms", state.current.avg_wait_ns as f64 / 1e6))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)))
        .data(&wait_data)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(wait_spark, rows[1]);

    // Queue Depth Sparkline
    let queue_data: Vec<u64> = state.queue_history.iter().cloned().collect();
    let queue_spark = Sparkline::default()
        .block(Block::default()
            .title(format!("Task Queue Depth: {}", state.current.tasks_in_queue))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)))
        .data(&queue_data)
        .style(Style::default().fg(Color::Magenta));
    f.render_widget(queue_spark, rows[2]);
}

fn draw_sidebar(f: &mut Frame, area: Rect, state: &AppState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(5)])
        .split(area);

    // Stats panel
    let io_color = if state.current.io_wait_percent > 30.0 { Color::Red } else { Color::Green };
    let cpu_color = if state.current.cpu_usage_percent > 80.0 { Color::Red }
                    else if state.current.cpu_usage_percent > 50.0 { Color::Yellow }
                    else { Color::Green };

    let stats_text = Text::from(vec![
        Line::from(vec![
            Span::raw("CPU:      "),
            Span::styled(
                format!("{:.1}%", state.current.cpu_usage_percent),
                Style::default().fg(cpu_color).add_modifier(Modifier::BOLD)
            ),
        ]),
        Line::from(vec![
            Span::raw("I/O Wait: "),
            Span::styled(
                format!("{:.1}%", state.current.io_wait_percent),
                Style::default().fg(io_color)
            ),
        ]),
        Line::from(format!("Ctx/s:    {}", state.current.context_switches_per_sec)),
        Line::from(format!("Queued:   {}", state.current.tasks_in_queue)),
        Line::raw(""),
        Line::from(vec![
            Span::raw(" AI: "),
            Span::styled(&state.last_ai_thought, Style::default().fg(Color::Cyan).add_modifier(Modifier::ITALIC)),
        ]),
    ]);

    let stats = Paragraph::new(stats_text)
        .block(Block::default()
            .title("Live Metrics")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)))
        .wrap(Wrap { trim: true });
    f.render_widget(stats, rows[0]);

    // Event log
    let items: Vec<ListItem> = state.log_entries.iter().rev()
        .map(|s| ListItem::new(s.as_str()))
        .collect();
    let log = List::new(items)
        .block(Block::default()
            .title("Event Log")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(log, rows[1]);
}

fn draw_footer(f: &mut Frame, area: Rect, _state: &AppState) {
    let text = Line::from(vec![
        Span::styled(" q ", Style::default().bg(Color::DarkGray).fg(Color::White)),
        Span::raw(" Quit  "),
        Span::styled(" f ", Style::default().bg(Color::DarkGray).fg(Color::White)),
        Span::raw(" Force CFS fallback  "),
        Span::styled(" r ", Style::default().bg(Color::DarkGray).fg(Color::White)),
        Span::raw(" Refresh  "),
        Span::raw("  SchedAI v0.1.0 -- AI-powered sched_ext scheduler"),
    ]);
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(para, area);
}

// --- Main ---------------------------------------------------------------------

fn main() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app        = AppState::new();
    let mut last_fetch = Instant::now();
    let fetch_interval = Duration::from_secs(2);

    app.add_log("SchedAI TUI Dashboard started".into());
    app.add_log("Connecting to MCP server at localhost:8080...".into());

    loop {
        term.draw(|f| draw(f, &app))?;

        // Non-blocking event poll (50ms timeout = ~20fps)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('f') => {
                        app.add_log("[WARN]  Manual CFS fallback triggered".into());
                        let _ = reqwest::blocking::Client::new()
                            .post("http://localhost:8080/mcp/call")
                            .json(&serde_json::json!({"tool": "fallback_to_cfs", "params": {}}))
                            .send();
                    }
                    KeyCode::Char('r') => {
                        last_fetch = Instant::now() - fetch_interval; // force refresh
                    }
                    _ => {}
                }
            }
        }

        // Fetch metrics from MCP server every 2 seconds
        if last_fetch.elapsed() >= fetch_interval {
            match reqwest::blocking::Client::new()
                .post("http://localhost:8080/mcp/call")
                .json(&serde_json::json!({"tool": "get_system_metrics", "params": {}}))
                .timeout(Duration::from_secs(2))
                .send()
            {
                Ok(resp) => {
                    if let Ok(body) = resp.json::<serde_json::Value>() {
                        if let Ok(metrics) = serde_json::from_value::<Metrics>(body["result"].clone()) {
                            app.push_metrics(metrics);
                        }
                    }
                }
                Err(_) => {
                    if app.frame_count % 10 == 0 {
                        app.add_log("[WARN]  MCP server not reachable -- is it running?".into());
                    }
                }
            }
            last_fetch = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;
    println!("SchedAI TUI closed. Goodbye!");
    Ok(())
}
