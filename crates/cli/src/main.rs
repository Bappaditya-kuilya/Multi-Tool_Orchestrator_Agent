//! `scopegatectl` — CLI and TUI client for a running ScopeGate gateway.
//!
//! This is a client only. It never modifies gateway state except through the
//! documented v1 approval-resolution endpoint.

use clap::{Parser, Subcommand};

use scopegate_ctl::client::Client;
use scopegate_ctl::{commands, tui};

#[derive(Parser, Debug)]
#[command(
    name = "scopegatectl",
    version,
    about = "Inspect and operate a local ScopeGate gateway"
)]
struct Cli {
    /// Gateway base URL (or SCOPEGATE_URL)
    #[arg(long, env = "SCOPEGATE_URL", default_value = "http://127.0.0.1:8080")]
    url: String,

    /// Bearer token sent as Authorization (or SCOPEGATE_TOKEN)
    #[arg(long, env = "SCOPEGATE_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show health, readiness, and metrics summary
    Status,
    /// Open the full-screen terminal UI
    Tui,
    /// List tasks
    Tasks,
    /// Inspect or resolve approvals
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// Inspect the audit log and verify its hash chain
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Show the active policy
    Policies,
}

#[derive(Subcommand, Debug)]
enum ApprovalAction {
    /// List approvals, optionally filtered by status
    List {
        #[arg(long)]
        status: Option<String>,
    },
    /// Resolve an approval: approve, deny, or timeout
    Resolve {
        id: String,
        #[arg(value_parser = ["approve", "deny", "timeout"])]
        decision: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditAction {
    /// Show recent audit events
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Verify the store-backed hash chain
    Verify,
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let client = Client::new(&cli.url, cli.token.clone());

    match cli.command {
        Command::Status => commands::status(&client),
        Command::Tui => tui::run(client),
        Command::Tasks => commands::tasks(&client),
        Command::Approvals { action } => match action {
            ApprovalAction::List { status } => commands::approvals(&client, status.as_deref()),
            ApprovalAction::Resolve { id, decision } => commands::resolve(&client, &id, &decision),
        },
        Command::Audit { action } => match action {
            AuditAction::List { limit } => commands::audit(&client, limit),
            AuditAction::Verify => commands::audit_verify(&client),
        },
        Command::Policies => commands::policy(&client),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("scopegatectl: {e}");
        std::process::exit(1);
    }
}
