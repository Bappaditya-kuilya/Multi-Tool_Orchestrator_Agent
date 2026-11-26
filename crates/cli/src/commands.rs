//! One-shot commands. Plain text output so output is pipeable.

use crate::client::Client;

pub fn status(client: &Client) -> Result<(), String> {
    let health = client.health()?;
    let ready = client.ready()?;
    let metrics = match client.metrics() {
        Ok(m) => format!("{} bytes ({})", m.body.len(), m.format),
        Err(e) => format!("unavailable ({e})"),
    };

    println!("endpoint : {}", client.endpoint());
    println!("health   : {}", health.status);
    println!(
        "ready    : {}{}",
        if ready.ready { "yes" } else { "no" },
        ready.reason.map(|r| format!(" ({r})")).unwrap_or_default()
    );
    println!("metrics  : {metrics}");

    if !ready.ready {
        return Err("gateway is not ready".to_string());
    }
    Ok(())
}

pub fn tasks(client: &Client) -> Result<(), String> {
    let tasks = client.tasks()?;
    println!("ID\tTOKEN\tBUDGET\tEXPIRES\tREVOKED");
    for t in tasks {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            t.id, t.token_id, t.budget, t.expires_at, t.revoked
        );
    }
    Ok(())
}

pub fn approvals(client: &Client, status: Option<&str>) -> Result<(), String> {
    let approvals = client.approvals(status)?;
    println!("ID\tTASK\tTOOL\tSTATUS\tCREATED");
    for a in approvals {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            a.id, a.task_id, a.tool, a.status, a.created_at
        );
    }
    Ok(())
}

pub fn resolve(client: &Client, id: &str, decision: &str) -> Result<(), String> {
    let view = client.resolve(id, decision)?;
    println!("{} -> {}", view.id, view.status);
    Ok(())
}

pub fn audit(client: &Client, limit: u32) -> Result<(), String> {
    let view = client.audit(limit)?;
    println!(
        "chain_verified={} events={}",
        view.chain_verified,
        view.events.len()
    );
    println!("SEQ\tTS\tTOOL\tDECISION\tREASON");
    for e in view.events {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            e.seq,
            e.ts,
            e.tool.unwrap_or_default(),
            e.decision,
            e.reason.unwrap_or_default()
        );
    }
    Ok(())
}

pub fn audit_verify(client: &Client) -> Result<(), String> {
    let report = client.audit_verify()?;
    println!(
        "ok={} checked_events={} first_bad_seq={:?}",
        report.ok, report.checked_events, report.first_bad_seq
    );
    if let Some(message) = report.message {
        println!("message: {message}");
    }
    if !report.ok {
        return Err("audit chain verification failed (fail-closed)".to_string());
    }
    Ok(())
}

pub fn policy(client: &Client) -> Result<(), String> {
    let p = client.policy()?;
    println!("id       : {}", p.id);
    println!("active   : {}", p.active);
    println!("version  : {:?}", p.version);
    if let Some(body) = p.body {
        println!("body     : {body}");
    }
    Ok(())
}
