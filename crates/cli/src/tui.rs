//! Full-screen terminal UI for inspecting and resolving ScopeGate state.

use std::io::{self, stdout};
use std::time::{Duration, Instant};

use crossterm::event::{poll, read, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::tty::IsTty;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{Frame, Terminal};

use crate::client::Client;
use crate::model::{
    ApprovalRecordView, AuditQueryView, Health, Metrics, PolicyView, Ready, TaskRecordView,
};

const TABS: [&str; 5] = ["Overview", "Approvals", "Audit", "Tasks", "Policies"];
const REFRESH_EVERY: Duration = Duration::from_secs(2);

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
    message: String,
    last_refresh: Instant,
    health: Result<Health, String>,
    ready: Result<Ready, String>,
    metrics: Result<Metrics, String>,
    tasks: Result<Vec<TaskRecordView>, String>,
    approvals: Result<Vec<ApprovalRecordView>, String>,
    audit: Result<AuditQueryView, String>,
    policy: Result<PolicyView, String>,
}

impl App {
    fn new(client: Client) -> Self {
        Self {
            client,
            tab: 0,
            selected: 0,
            message: "ready".to_string(),
            last_refresh: Instant::now() - REFRESH_EVERY,
            health: Err("not loaded".into()),
            ready: Err("not loaded".into()),
            metrics: Err("not loaded".into()),
            tasks: Err("not loaded".into()),
            approvals: Err("not loaded".into()),
            audit: Err("not loaded".into()),
            policy: Err("not loaded".into()),
        }
    }

    fn refresh(&mut self) {
        self.health = self.client.health();
        self.ready = self.client.ready();
        self.metrics = self.client.metrics();
        self.tasks = self.client.tasks();
        self.approvals = self.client.approvals(None);
        self.audit = self.client.audit(100);
        self.policy = self.client.policy();
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
        self.message = match self.client.resolve(&id, decision) {
            Ok(view) => format!("{id} -> {}", view.status),
            Err(e) => format!("resolve failed: {e}"),
        };
        self.refresh();
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
                        KeyCode::Tab | KeyCode::Right => {
                            self.tab = (self.tab + 1) % TABS.len();
                            self.selected = 0;
                        }
                        KeyCode::Left => {
                            self.tab = (self.tab + TABS.len() - 1) % TABS.len();
                            self.selected = 0;
                        }
                        KeyCode::Down => self.move_selection(1),
                        KeyCode::Up => self.move_selection(-1),
                        KeyCode::Char('r') => self.refresh(),
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

    fn draw(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<(), String> {
        terminal
            .draw(|f| self.render(f))
            .map(|_| ())
            .map_err(|e| format!("draw error: {e}"))
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(f.area());

        let tabs = Tabs::new(
            TABS.iter()
                .map(|t| Line::from(Span::raw(*t)))
                .collect::<Vec<_>>(),
        )
        .select(self.tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("scopegatectl - local preview"),
        );
        f.render_widget(tabs, chunks[0]);

        match self.tab {
            0 => self.render_overview(f, chunks[1]),
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
                render_table(
                    f,
                    chunks[1],
                    "Approvals (a=approve d=deny x=timeout)",
                    &["ID", "Task", "Tool", "Status", "Created"],
                    &rows,
                    self.selected,
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
                let chain = match &self.audit {
                    Ok(v) => format!("chain_verified={}", v.chain_verified),
                    Err(_) => "chain_verified=unknown".to_string(),
                };
                render_table(
                    f,
                    chunks[1],
                    &format!("Audit ({chain})"),
                    &["Seq", "TS", "Tool", "Decision", "Reason"],
                    &rows,
                    self.selected,
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
                render_table(
                    f,
                    chunks[1],
                    "Tasks",
                    &["ID", "Token", "Budget", "Expires", "Revoked"],
                    &rows,
                    self.selected,
                );
            }
            _ => {
                let text = match &self.policy {
                    Ok(p) => format!("{p:#?}"),
                    Err(e) => format!("error: {e}"),
                };
                let paragraph = Paragraph::new(text).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Active policy"),
                );
                f.render_widget(paragraph, chunks[1]);
            }
        }

        let footer = Paragraph::new(Line::from(vec![
            Span::raw("Tab/←→ switch  "),
            Span::raw("↑↓ select  "),
            Span::raw("r refresh  "),
            Span::raw("q quit  |  "),
            Span::styled(self.message.clone(), Style::default().fg(Color::Green)),
        ]))
        .block(Block::default().borders(Borders::ALL).title("Keys"));
        f.render_widget(footer, chunks[2]);
    }

    fn render_overview(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let line = |label: &str, value: &Result<String, String>| {
            let (text, color) = match value {
                Ok(v) => (v.clone(), Color::White),
                Err(e) => (e.clone(), Color::Red),
            };
            Line::from(vec![
                Span::styled(format!("{label:<12}"), Style::default().fg(Color::Yellow)),
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
            Line::from(Span::styled(
                format!("endpoint: {}", self.client.endpoint()),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            line("health", &health),
            line("ready", &ready),
            line("metrics", &metrics),
            line("approvals", &approvals),
            line("tasks", &tasks),
            line("audit", &audit),
            Line::from(""),
            Line::from(Span::styled(
                "Evidence only: this is a local preview client, not a sign-off surface.",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let paragraph =
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Overview"));
        f.render_widget(paragraph, area);
    }
}

fn render_table(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    title: &str,
    headers: &[&str],
    rows: &[Vec<String>],
    selected: usize,
) {
    let header = Row::new(
        headers
            .iter()
            .map(|h| Cell::from(Span::styled(*h, Style::default().fg(Color::Yellow)))),
    )
    .bottom_margin(0);

    let width = 100 / headers.len().max(1) as u16;
    let constraints = vec![Constraint::Percentage(width); headers.len()];

    let body = rows.iter().enumerate().map(|(i, row)| {
        let style = if i == selected {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        Row::new(row.iter().map(|cell| Cell::from(cell.as_str()))).style(style)
    });

    let table = Table::new(body, constraints).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title.to_string()),
    );
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
    execute!(stdout(), EnterAlternateScreen)
        .map_err(|e| format!("cannot enter alternate screen: {e}"))?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("cannot create terminal: {e}"))?;
    let mut app = App::new(client);
    app.refresh();
    app.event_loop(&mut terminal)
}
