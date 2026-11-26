//! Full-screen "btop/abtop"-style terminal dashboard for ScopeGate.
//!
//! Live header, gauges, traffic sparklines fed by the gateway's Prometheus
//! counters, colour-coded tables, a keybinding strip, and switchable themes.

use std::io::{self, stdout};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{poll, read, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::tty::IsTty;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table, Tabs, Wrap,
};
use ratatui::{Frame, Terminal};

use crate::client::Client;
use crate::metrics::{parse_counters, push_history, Counters};
use crate::model::{
    ApprovalRecordView, AuditQueryView, Health, Metrics, PolicyView, Ready, TaskRecordView,
};

const TABS: [&str; 5] = ["Overview", "Approvals", "Audit", "Tasks", "Policies"];
const REFRESH_EVERY: Duration = Duration::from_secs(2);
const HISTORY: usize = 48;

#[derive(Clone, Copy)]
struct Theme {
    name: &'static str,
    accent: Color,
    good: Color,
    warn: Color,
    bad: Color,
    muted: Color,
}

const THEMES: [Theme; 3] = [
    Theme {
        name: "btop",
        accent: Color::Cyan,
        good: Color::Green,
        warn: Color::Yellow,
        bad: Color::Red,
        muted: Color::Gray,
    },
    Theme {
        name: "amber",
        accent: Color::Yellow,
        good: Color::Green,
        warn: Color::Magenta,
        bad: Color::Red,
        muted: Color::Gray,
    },
    Theme {
        name: "mono",
        accent: Color::White,
        good: Color::White,
        warn: Color::Gray,
        bad: Color::White,
        muted: Color::DarkGray,
    },
];

struct Spark<'a> {
    title: &'static str,
    data: &'a [u64],
    color: Color,
    total: u64,
}

/// Restore the terminal even if the event loop exits with an error.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

struct App {
    client: Client,
    tab: usize,
    selected: usize,
    theme_index: usize,
    message: String,
    last_refresh: Instant,
    health: Result<Health, String>,
    ready: Result<Ready, String>,
    metrics: Result<Metrics, String>,
    tasks: Result<Vec<TaskRecordView>, String>,
    approvals: Result<Vec<ApprovalRecordView>, String>,
    audit: Result<AuditQueryView, String>,
    policy: Result<PolicyView, String>,
    last_counters: Counters,
    requests: Vec<u64>,
    denied: Vec<u64>,
    audits: Vec<u64>,
}

impl App {
    fn new(client: Client) -> Self {
        Self {
            client,
            tab: 0,
            selected: 0,
            theme_index: 0,
            message: "ready".to_string(),
            last_refresh: Instant::now() - REFRESH_EVERY,
            health: Err("not loaded".into()),
            ready: Err("not loaded".into()),
            metrics: Err("not loaded".into()),
            tasks: Err("not loaded".into()),
            approvals: Err("not loaded".into()),
            audit: Err("not loaded".into()),
            policy: Err("not loaded".into()),
            last_counters: Counters::default(),
            requests: Vec::new(),
            denied: Vec::new(),
            audits: Vec::new(),
        }
    }

    fn theme(&self) -> Theme {
        THEMES[self.theme_index]
    }

    fn refresh(&mut self) {
        self.health = self.client.health();
        self.ready = self.client.ready();
        self.metrics = self.client.metrics();
        self.tasks = self.client.tasks();
        self.approvals = self.client.approvals(None);
        self.audit = self.client.audit(100);
        self.policy = self.client.policy();

        if let Ok(metrics) = &self.metrics {
            let now = parse_counters(&metrics.body);
            let delta = self.last_counters.delta(&now);
            push_history(&mut self.requests, delta.requests, HISTORY);
            push_history(&mut self.denied, delta.denied, HISTORY);
            push_history(&mut self.audits, delta.audit_appends, HISTORY);
            self.last_counters = now;
        }

        self.last_refresh = Instant::now();
        self.message = "refreshed".to_string();
        let len = self.current_len();
        if self.selected >= len && len > 0 {
            self.selected = len - 1;
        }
    }

    fn current_len(&self) -> usize {
        match self.tab {
            1 => self.approvals.as_ref().map(|v| v.len()).unwrap_or(0),
            2 => self.audit.as_ref().map(|v| v.events.len()).unwrap_or(0),
            3 => self.tasks.as_ref().map(|v| v.len()).unwrap_or(0),
            _ => 0,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.current_len();
        if len == 0 {
            return;
        }
        let next = self.selected as isize + delta;
        if next >= 0 && (next as usize) < len {
            self.selected = next as usize;
        }
    }

    fn resolve_selected(&mut self, decision: &str) {
        let id = match &self.approvals {
            Ok(list) => list.get(self.selected).map(|a| a.id.clone()),
            Err(_) => None,
        };
        let Some(id) = id else {
            self.message = "no approval selected".to_string();
            return;
        };
        let result = match self.client.resolve(&id, decision) {
            Ok(view) => format!("{id} -> {}", view.status),
            Err(e) => format!("resolve failed: {e}"),
        };
        self.refresh();
        self.message = result;
    }

    fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<(), String> {
        self.draw(terminal)?;
        loop {
            if poll(Duration::from_millis(200)).map_err(|e| format!("input error: {e}"))? {
                if let Event::Key(key) = read().map_err(|e| format!("input error: {e}"))? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Tab | KeyCode::Right => self.next_tab(1),
                        KeyCode::Left => self.next_tab(TABS.len() - 1),
                        KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
                        KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
                        KeyCode::Char('r') => self.refresh(),
                        KeyCode::Char('t') => {
                            self.theme_index = (self.theme_index + 1) % THEMES.len();
                            self.message = format!("theme: {}", self.theme().name);
                        }
                        KeyCode::Char('a') | KeyCode::Enter if self.tab == 1 => {
                            self.resolve_selected("approve")
                        }
                        KeyCode::Char('d') if self.tab == 1 => self.resolve_selected("deny"),
                        KeyCode::Char('x') if self.tab == 1 => self.resolve_selected("timeout"),
                        _ => {}
                    }
                }
            }
            if self.last_refresh.elapsed() >= REFRESH_EVERY {
                self.refresh();
            }
            self.draw(terminal)?;
        }
    }

    fn next_tab(&mut self, step: usize) {
        self.tab = (self.tab + step) % TABS.len();
        self.selected = 0;
    }

    fn draw(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<(), String> {
        terminal
            .draw(|f| self.render(f))
            .map(|_| ())
            .map_err(|e| format!("draw error: {e}"))
    }

    fn render(&self, f: &mut Frame) {
        let theme = self.theme();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // header
                Constraint::Length(11), // gauges + sparklines
                Constraint::Length(3),  // tabs
                Constraint::Min(4),     // body
                Constraint::Length(3),  // keys
                Constraint::Length(3),  // message
            ])
            .split(f.area());

        self.render_header(f, chunks[0], theme);
        self.render_top(f, chunks[1], theme);
        self.render_tabs(f, chunks[2], theme);
        self.render_body(f, chunks[3], theme);
        self.render_keys(f, chunks[4], theme);
        self.render_message(f, chunks[5], theme);
    }

    fn render_header(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let connected = self.health.is_ok();
        let line = Line::from(vec![
            Span::styled(
                " scopegatectl ",
                Style::default()
                    .fg(Color::Black)
                    .bg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" v0.1.0  "),
            Span::styled(self.client.endpoint(), Style::default().fg(theme.accent)),
            Span::raw("   "),
            dot(connected, theme.good, theme.bad),
            Span::raw(if connected {
                " connected"
            } else {
                " disconnected"
            }),
            Span::raw("   "),
            Span::styled(clock(), Style::default().fg(theme.warn)),
            Span::raw("   theme:"),
            Span::styled(theme.name, Style::default().fg(theme.accent)),
            Span::raw("   2s"),
        ]);
        let paragraph = Paragraph::new(line).block(section("SCOPEGATE", theme.accent));
        f.render_widget(paragraph, area);
    }

    fn render_top(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(area);

        // Left: status + gauges.
        let health_ok = self.health.is_ok();
        let ready_ok = self.ready.as_ref().map(|r| r.ready).unwrap_or(false);
        let chain_ok = self
            .audit
            .as_ref()
            .map(|v| v.chain_verified)
            .unwrap_or(false);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(cols[0].inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

        let status_line = |label: &str, ok: bool, detail: String| {
            let detail: String = detail.chars().take(42).collect();
            Line::from(vec![
                Span::styled(format!("{label:<9}"), Style::default().fg(theme.muted)),
                dot(ok, theme.good, theme.bad),
                Span::raw(format!(" {detail}")),
            ])
        };
        let ready_detail = self
            .ready
            .as_ref()
            .map(|r| {
                if r.ready {
                    "YES".to_string()
                } else {
                    format!("NO ({})", r.reason.as_deref().unwrap_or("unknown"))
                }
            })
            .unwrap_or_else(|e| format!("ERR ({e})"));
        let health_detail = match &self.health {
            Ok(h) => h.status.clone(),
            Err(e) => format!("ERR ({e})"),
        };
        f.render_widget(
            Paragraph::new(status_line("health", health_ok, health_detail)),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(status_line("ready", ready_ok, ready_detail)),
            rows[1],
        );
        f.render_widget(
            Gauge::default()
                .block(Block::default().title(" readiness ").borders(Borders::ALL))
                .gauge_style(Style::default().fg(if ready_ok { theme.good } else { theme.bad }))
                .ratio(if ready_ok { 1.0 } else { 0.0 })
                .label(if ready_ok { "READY" } else { "NOT READY" }),
            rows[2],
        );
        f.render_widget(
            Gauge::default()
                .block(
                    Block::default()
                        .title(" audit chain ")
                        .borders(Borders::ALL),
                )
                .gauge_style(Style::default().fg(if chain_ok { theme.good } else { theme.bad }))
                .ratio(if chain_ok { 1.0 } else { 0.0 })
                .label(if chain_ok { "VERIFIED" } else { "UNVERIFIED" }),
            rows[3],
        );
        f.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title("GATEWAY")
                .border_style(Style::default().fg(theme.accent)),
            cols[0],
        );

        // Right: traffic sparklines.
        let graph_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(cols[1]);
        self.render_sparkline(
            f,
            graph_rows[0],
            theme,
            &Spark {
                title: "REQUESTS / 2s",
                data: &self.requests,
                color: theme.accent,
                total: self.last_counters.requests,
            },
        );
        self.render_sparkline(
            f,
            graph_rows[1],
            theme,
            &Spark {
                title: "AUDIT APPENDS / 2s",
                data: &self.audits,
                color: theme.good,
                total: self.last_counters.audit_appends,
            },
        );
    }

    fn render_sparkline(&self, f: &mut Frame, area: Rect, theme: Theme, spec: &Spark<'_>) {
        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let label = Line::from(vec![
            Span::styled(spec.title, Style::default().fg(theme.muted)),
            Span::raw("   total "),
            Span::styled(
                spec.total.to_string(),
                Style::default().fg(spec.color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("   denied "),
            Span::styled(
                self.last_counters.denied.to_string(),
                Style::default().fg(theme.bad),
            ),
        ]);
        f.render_widget(Paragraph::new(label), inner);
        let graph = Rect {
            y: inner.y + 1,
            height: inner.height.saturating_sub(1),
            ..inner
        };
        let sample = if spec.data.is_empty() {
            &[0u64][..]
        } else {
            spec.data
        };
        let peak = spec.data.iter().copied().max().unwrap_or(1).max(1);
        let spark = Sparkline::default()
            .data(sample)
            .max(peak)
            .style(Style::default().fg(spec.color));
        f.render_widget(spark, graph);
        f.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title("TRAFFIC")
                .border_style(Style::default().fg(theme.accent)),
            area,
        );
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let tabs = Tabs::new(
            TABS.iter()
                .map(|t| Line::from(Span::raw(*t)))
                .collect::<Vec<_>>(),
        )
        .select(self.tab)
        .highlight_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::raw("│"))
        .block(section("VIEWS", theme.muted));
        f.render_widget(tabs, area);
    }

    fn render_body(&self, f: &mut Frame, area: Rect, theme: Theme) {
        match self.tab {
            1 => {
                let rows = match &self.approvals {
                    Ok(list) => list
                        .iter()
                        .map(|a| {
                            vec![
                                a.id.clone(),
                                a.task_id.clone(),
                                a.tool.clone(),
                                a.status.clone(),
                                a.created_at.clone(),
                            ]
                        })
                        .collect::<Vec<_>>(),
                    Err(e) => vec![vec![format!("error: {e}")]],
                };
                status_table(
                    f,
                    area,
                    theme,
                    "APPROVALS  ·  a approve / d deny / x timeout",
                    &["ID", "Task", "Tool", "Status", "Created"],
                    &rows,
                    self.selected,
                    3,
                );
            }
            2 => {
                let rows = match &self.audit {
                    Ok(view) => view
                        .events
                        .iter()
                        .map(|e| {
                            vec![
                                e.seq.to_string(),
                                e.ts.clone(),
                                e.tool.clone().unwrap_or_default(),
                                e.decision.clone(),
                                e.reason.clone().unwrap_or_default(),
                            ]
                        })
                        .collect::<Vec<_>>(),
                    Err(e) => vec![vec![format!("error: {e}")]],
                };
                status_table(
                    f,
                    area,
                    theme,
                    "AUDIT LOG",
                    &["Seq", "TS", "Tool", "Decision", "Reason"],
                    &rows,
                    self.selected,
                    3,
                );
            }
            3 => {
                let rows = match &self.tasks {
                    Ok(list) => list
                        .iter()
                        .map(|t| {
                            vec![
                                t.id.clone(),
                                t.token_id.clone(),
                                t.budget.to_string(),
                                t.expires_at.clone(),
                                t.revoked.to_string(),
                            ]
                        })
                        .collect::<Vec<_>>(),
                    Err(e) => vec![vec![format!("error: {e}")]],
                };
                status_table(
                    f,
                    area,
                    theme,
                    "TASKS",
                    &["ID", "Token", "Budget", "Expires", "Revoked"],
                    &rows,
                    self.selected,
                    4,
                );
            }
            4 => {
                let text = match &self.policy {
                    Ok(p) => format!("{p:#?}"),
                    Err(e) => format!("error: {e}"),
                };
                let paragraph = Paragraph::new(text)
                    .wrap(Wrap { trim: true })
                    .block(section("ACTIVE POLICY", theme.accent));
                f.render_widget(paragraph, area);
            }
            _ => self.render_overview(f, area, theme),
        }
    }

    fn render_overview(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let value = |label: &str, result: Result<String, String>| {
            let (text, color) = match result {
                Ok(v) => (v, theme.accent),
                Err(e) => (e, theme.bad),
            };
            Line::from(vec![
                Span::styled(format!("{label:<14}"), Style::default().fg(theme.muted)),
                Span::styled(text, Style::default().fg(color)),
            ])
        };
        let health = self
            .health
            .as_ref()
            .map(|h| h.status.clone())
            .map_err(|e| e.clone());
        let ready = self
            .ready
            .as_ref()
            .map(|r| {
                format!(
                    "{}{}",
                    r.ready,
                    r.reason
                        .as_ref()
                        .map(|x| format!(" ({x})"))
                        .unwrap_or_default()
                )
            })
            .map_err(|e| e.clone());
        let metrics = self
            .metrics
            .as_ref()
            .map(|m| format!("{} bytes ({})", m.body.len(), m.format))
            .map_err(|e| e.clone());
        let approvals = self
            .approvals
            .as_ref()
            .map(|v| format!("{} records", v.len()))
            .map_err(|e| e.clone());
        let tasks = self
            .tasks
            .as_ref()
            .map(|v| format!("{} records", v.len()))
            .map_err(|e| e.clone());
        let audit = self
            .audit
            .as_ref()
            .map(|v| format!("{} events, verified={}", v.events.len(), v.chain_verified))
            .map_err(|e| e.clone());

        let lines = vec![
            value("endpoint", Ok(self.client.endpoint().to_string())),
            value("health", health),
            value("ready", ready),
            value("metrics", metrics),
            value("approvals", approvals),
            value("tasks", tasks),
            value("audit", audit),
            value("requests", Ok(self.last_counters.requests.to_string())),
            value("denied", Ok(self.last_counters.denied.to_string())),
            Line::from(""),
            Line::from(Span::styled(
                "Evidence only: local preview client, not a sign-off surface.",
                Style::default().fg(theme.muted),
            )),
        ];
        f.render_widget(
            Paragraph::new(lines).block(section("OVERVIEW", theme.accent)),
            area,
        );
    }

    fn render_keys(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let keys = Line::from(vec![
            key("q", "quit", theme),
            key("j/k ↑↓", "select", theme),
            key("Tab ←→", "views", theme),
            key("r", "refresh", theme),
            key("a/d/x", "resolve", theme),
            key("t", "theme", theme),
        ]);
        f.render_widget(
            Paragraph::new(keys).block(section("KEYS", theme.muted)),
            area,
        );
    }

    fn render_message(&self, f: &mut Frame, area: Rect, theme: Theme) {
        let line = Line::from(vec![
            Span::styled(" last  ", Style::default().fg(theme.muted)),
            Span::styled(self.message.clone(), Style::default().fg(theme.good)),
        ]);
        f.render_widget(
            Paragraph::new(line).block(section("STATUS", theme.muted)),
            area,
        );
    }
}

fn section<'a>(title: &'a str, color: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(format!(" {} ", title))
        .border_style(Style::default().fg(color))
}

fn dot<'a>(ok: bool, good: Color, bad: Color) -> Span<'a> {
    if ok {
        Span::styled("●", Style::default().fg(good))
    } else {
        Span::styled("●", Style::default().fg(bad))
    }
}

fn key<'a>(name: &'a str, action: &'a str, theme: Theme) -> Span<'a> {
    Span::raw(format!(" {name}:{action} ",)).style(Style::default().fg(theme.muted))
}

fn clock() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

#[allow(clippy::too_many_arguments)]
fn status_table(
    f: &mut Frame,
    area: Rect,
    theme: Theme,
    title: &str,
    headers: &[&str],
    rows: &[Vec<String>],
    selected: usize,
    status_col: usize,
) {
    let header = Row::new(
        headers
            .iter()
            .map(|h| Cell::from(Span::styled(*h, Style::default().fg(theme.accent)))),
    );
    let width = 100 / headers.len().max(1) as u16;
    let constraints = vec![Constraint::Percentage(width); headers.len()];
    let body = rows.iter().enumerate().map(|(i, row)| {
        let selected_style = if i == selected {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let cells = row.iter().enumerate().map(|(col, cell)| {
            if col == status_col {
                let value = cell.to_ascii_lowercase();
                let color =
                    if value.contains("approve") || value.contains("allow") || value.contains("ok")
                    {
                        theme.good
                    } else if value.contains("deny")
                        || value.contains("reject")
                        || value.contains("fail")
                    {
                        theme.bad
                    } else if value.contains("pending")
                        || value.contains("expire")
                        || value.contains("timeout")
                    {
                        theme.warn
                    } else {
                        selected_style.fg.unwrap_or(Color::Reset)
                    };
                Cell::from(cell.as_str()).style(Style::default().fg(color))
            } else {
                Cell::from(cell.as_str())
            }
        });
        Row::new(cells).style(selected_style)
    });
    let table = Table::new(body, constraints)
        .header(header)
        .block(section(title, theme.accent));
    f.render_widget(table, area);
}

/// Enter the alternate screen, run the UI, and always restore the terminal.
pub fn run(client: Client) -> Result<(), String> {
    if !stdout().is_tty() {
        return Err(
            "TUI requires an interactive terminal; use the one-shot commands instead".into(),
        );
    }
    enable_raw_mode().map_err(|e| format!("cannot enable raw mode: {e}"))?;
    let _guard = TerminalGuard;
    execute!(stdout(), EnterAlternateScreen)
        .map_err(|e| format!("cannot enter alternate screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("cannot create terminal: {e}"))?;
    let mut app = App::new(client);
    app.refresh();
    app.event_loop(&mut terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn dashboard_renders_header_gauges_and_tables() {
        let backend = TestBackend::new(140, 40);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        let mut app = App::new(Client::new("http://127.0.0.1:8080", None));
        app.health = Ok(Health {
            status: "ok".to_string(),
        });
        app.ready = Ok(Ready {
            ready: true,
            reason: None,
        });
        app.audit = Ok(AuditQueryView {
            chain_verified: true,
            ..Default::default()
        });
        app.metrics = Ok(Metrics {
            body: "gateway_requests_total 7\n".to_string(),
            format: "text/plain".to_string(),
        });
        app.approvals = Ok(vec![ApprovalRecordView {
            id: "ap-1".to_string(),
            task_id: "task-1".to_string(),
            tool: "tools/call".to_string(),
            status: "pending".to_string(),
            created_at: "0".to_string(),
        }]);
        app.tab = 1;

        terminal.draw(|f| app.render(f)).expect("render");

        let buffer = terminal.backend().buffer();
        let rendered: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        for expected in [
            "scopegatectl",
            "TRAFFIC",
            "GATEWAY",
            "APPROVALS",
            "ap-1",
            "VERIFIED",
            "theme:btop",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?} in rendered dashboard"
            );
        }
    }
}
