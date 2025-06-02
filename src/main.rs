use std::env;
use std::process::Command;

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "phone-monitor")]
#[command(about = "A Kubernetes-native phone presence monitor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the web server (default mode)
    Serve,
    /// Scan the network for devices
    Scan,
    /// Check if alerts need to be sent
    CheckAlerts,
    /// Handle incoming SMS responses
    HandleResponse,
    /// Initialize the monitoring system
    Init,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    phone_mac_addresses: Vec<String>,
    my_phone_number: String,
    friend_phone_numbers: Vec<String>,
    network_subnet: String,
    absence_threshold_hours: i64,
    escalation_timeout_hours: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DeviceRecord {
    mac_address: String,
    ip_address: String,
    hostname: Option<String>,
    last_seen: DateTime<Utc>,
    vendor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AlertRecord {
    id: String,
    phone_number: String,
    alert_type: String, // "initial" or "escalated"
    sent_at: DateTime<Utc>,
    responded_at: Option<DateTime<Utc>>,
    is_active: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct MonitoringState {
    devices: std::collections::HashMap<String, DeviceRecord>,
    alerts: Vec<AlertRecord>,
    last_scan: Option<DateTime<Utc>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => run_server().await?,
        Commands::Scan => scan_network().await?,
        Commands::CheckAlerts => check_and_send_alerts().await?,
        Commands::HandleResponse => handle_sms_response().await?,
        Commands::Init => init_monitoring().await?,
    }

    Ok(())
}

async fn run_server() -> Result<()> {
    use axum::{
        Router,
        extract::{Form, State},
        http::StatusCode,
        response::Json,
        routing::{get, post},
    };
    use tokio::time::{Duration, interval};

    #[derive(Clone)]
    struct AppState {}

    #[derive(Debug, serde::Deserialize)]
    struct TwilioWebhookBody {
        #[serde(rename = "Body")]
        body: Option<String>,
    }

    let state = AppState {};

    // Start background tasks
    tokio::spawn(async move {
        let mut scan_interval = interval(Duration::from_secs(3600)); // 1 hour
        loop {
            scan_interval.tick().await;
            if let Err(e) = scan_network().await {
                error!("Background scan failed: {}", e);
            }
        }
    });

    tokio::spawn(async move {
        let mut alert_interval = interval(Duration::from_secs(1800)); // 30 minutes
        loop {
            alert_interval.tick().await;
            if let Err(e) = check_and_send_alerts().await {
                error!("Background alert check failed: {}", e);
            }
        }
    });

    async fn health_check() -> Json<serde_json::Value> {
        Json(serde_json::json!({"status": "healthy", "service": "phone-monitor"}))
    }

    async fn get_status(
        State(_state): State<AppState>,
    ) -> Result<Json<serde_json::Value>, StatusCode> {
        match get_monitoring_status().await {
            Ok(status) => Ok(Json(status)),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    async fn handle_webhook(
        State(_state): State<AppState>,
        Form(webhook_data): Form<TwilioWebhookBody>,
    ) -> Result<String, StatusCode> {
        info!("Received webhook: {:?}", webhook_data);

        if let Some(body) = webhook_data.body {
            let body_lower = body.to_lowercase();

            if body_lower.contains("ok")
                || body_lower.contains("safe")
                || body_lower.contains("fine")
                || body_lower.contains("good")
            {
                info!("Received positive response: {}", body);

                match handle_sms_response().await {
                    Ok(_) => {
                        info!("Successfully processed safety response");
                        return Ok("Thank you for confirming you're safe!".to_string());
                    }
                    Err(e) => {
                        error!("Failed to process response: {}", e);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            }
        }

        Ok("Message received".to_string())
    }

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(get_status))
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Phone monitor server running on http://0.0.0.0:8080");
    info!("Webhook endpoint: http://0.0.0.0:8080/webhook");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn scan_network() -> Result<()> {
    info!("Starting network scan...");

    let config = load_config().await?;
    let mut state = load_monitoring_state().await?;

    // Perform network scan
    let discovered_devices = perform_network_scan(&config.network_subnet).await?;

    // Update device records
    for device in discovered_devices {
        state.devices.insert(device.mac_address.clone(), device);
    }

    state.last_scan = Some(Utc::now());

    // Save updated state
    save_monitoring_state(&state).await?;

    info!(
        "Network scan completed. Found {} devices",
        state.devices.len()
    );
    Ok(())
}

async fn check_and_send_alerts() -> Result<()> {
    info!("Checking for alert conditions...");

    let config = load_config().await?;
    let mut state = load_monitoring_state().await?;

    for target_mac in &config.phone_mac_addresses {
        if let Some(device) = state.devices.get(target_mac) {
            let hours_absent = (Utc::now() - device.last_seen).num_hours();

            if hours_absent >= config.absence_threshold_hours {
                handle_absence_alert(&config, &mut state, target_mac, hours_absent).await?;
            }
        } else {
            warn!("Target device {} never seen on network", target_mac);
        }
    }

    save_monitoring_state(&state).await?;
    Ok(())
}

async fn handle_absence_alert(
    config: &Config,
    state: &mut MonitoringState,
    mac_address: &str,
    hours_absent: i64,
) -> Result<()> {
    // Check if there's already an active alert for this device
    let active_alert = state
        .alerts
        .iter()
        .find(|a| a.is_active && a.phone_number == config.my_phone_number);

    match active_alert {
        None => {
            // Send initial alert
            send_initial_alert(config, state, mac_address, hours_absent).await?;
        }
        Some(alert) => {
            let hours_since_alert = (Utc::now() - alert.sent_at).num_hours();

            // Check if we need to escalate and haven't responded
            if hours_since_alert >= config.escalation_timeout_hours
                && alert.responded_at.is_none()
                && alert.alert_type == "initial"
            {
                escalate_alert(config, state, mac_address).await?;
            }
        }
    }

    Ok(())
}

async fn send_initial_alert(
    config: &Config,
    state: &mut MonitoringState,
    mac_address: &str,
    hours_absent: i64,
) -> Result<()> {
    let message = format!(
        "🚨 Phone Alert: Your device hasn't been seen on home network for {} hours. Reply 'OK' if safe.",
        hours_absent
    );

    let alert_id = uuid::Uuid::new_v4().to_string();

    // Send SMS
    send_sms(&config.my_phone_number, &message).await?;

    // Record alert
    state.alerts.push(AlertRecord {
        id: alert_id,
        phone_number: config.my_phone_number.clone(),
        alert_type: "initial".to_string(),
        sent_at: Utc::now(),
        responded_at: None,
        is_active: true,
    });

    info!("Sent initial alert for device {}", mac_address);
    Ok(())
}

async fn escalate_alert(
    config: &Config,
    state: &mut MonitoringState,
    mac_address: &str,
) -> Result<()> {
    let message = format!(
        "🚨 URGENT: {} hasn't responded to safety check. Phone missing from network 24+ hours. Please check on them!",
        config.my_phone_number
    );

    // Send to all emergency contacts
    for friend_number in &config.friend_phone_numbers {
        send_sms(friend_number, &message).await?;

        state.alerts.push(AlertRecord {
            id: uuid::Uuid::new_v4().to_string(),
            phone_number: friend_number.clone(),
            alert_type: "escalated".to_string(),
            sent_at: Utc::now(),
            responded_at: None,
            is_active: true,
        });
    }

    // Mark original alert as escalated (inactive)
    if let Some(alert) = state
        .alerts
        .iter_mut()
        .find(|a| a.is_active && a.phone_number == config.my_phone_number)
    {
        alert.is_active = false;
    }

    warn!("Escalated alert for device {}", mac_address);
    Ok(())
}

async fn send_sms(phone_number: &str, message: &str) -> Result<()> {
    let twilio_sid = env::var("TWILIO_ACCOUNT_SID")?;
    let twilio_token = env::var("TWILIO_AUTH_TOKEN")?;
    let twilio_number = env::var("TWILIO_PHONE_NUMBER")?;

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        twilio_sid
    );

    let params = [
        ("To", phone_number),
        ("From", &twilio_number),
        ("Body", message),
    ];

    let response = client
        .post(&url)
        .basic_auth(&twilio_sid, Some(&twilio_token))
        .form(&params)
        .send()
        .await?;

    if response.status().is_success() {
        info!("SMS sent successfully to {}", phone_number);
    } else {
        error!(
            "Failed to send SMS to {}: {}",
            phone_number,
            response.status()
        );
    }

    Ok(())
}

async fn perform_network_scan(subnet: &str) -> Result<Vec<DeviceRecord>> {
    info!("Scanning network subnet: {}", subnet);

    // Use nmap to scan the network
    let output = Command::new("nmap")
        .args([
            "-sn", // Ping scan only
            "--host-timeout",
            "30s",
            subnet,
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("nmap scan failed"));
    }

    let scan_output = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();
    let now = Utc::now();

    // Parse nmap output to extract IP addresses
    let mut current_ip = None;
    for line in scan_output.lines() {
        if line.contains("Nmap scan report for") {
            // Extract IP address
            if let Some(ip) = extract_ip_from_line(line) {
                current_ip = Some(ip);
            }
        } else if line.contains("Host is up") && current_ip.is_some() {
            let ip = current_ip.take().unwrap();

            // Get MAC address using ARP
            if let Ok(mac) = get_mac_address(&ip).await {
                let vendor = get_vendor_from_mac(&mac).await.ok();
                let hostname = get_hostname(&ip).await.ok();

                devices.push(DeviceRecord {
                    mac_address: mac,
                    ip_address: ip,
                    hostname,
                    last_seen: now,
                    vendor,
                });
            }
        }
    }

    info!("Network scan found {} active devices", devices.len());
    Ok(devices)
}

async fn get_mac_address(ip: &str) -> Result<String> {
    // Try ARP table first
    let output = Command::new("arp").args(["-n", ip]).output()?;

    let arp_output = String::from_utf8_lossy(&output.stdout);

    for line in arp_output.lines() {
        if line.contains(ip) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let mac = parts[2];
                if mac.contains(':') && mac.len() == 17 {
                    return Ok(mac.to_lowercase());
                }
            }
        }
    }

    Err(anyhow::anyhow!("Could not find MAC address for IP {}", ip))
}

async fn get_vendor_from_mac(mac: &str) -> Result<String> {
    // Simple vendor lookup based on OUI (first 3 octets)
    let oui = &mac[..8].replace(':', "").to_uppercase();

    match oui.as_str() {
        "000000" => Ok("Unknown".to_string()),
        "AABBCC" => Ok("Apple".to_string()),
        "DDEEFF" => Ok("Samsung".to_string()),
        _ => Ok("Unknown".to_string()),
    }
}

async fn get_hostname(ip: &str) -> Result<String> {
    let output = Command::new("nslookup").arg(ip).output()?;

    let nslookup_output = String::from_utf8_lossy(&output.stdout);

    for line in nslookup_output.lines() {
        if line.contains("name =") {
            if let Some(hostname) = line.split("name = ").nth(1) {
                return Ok(hostname.trim_end_matches('.').to_string());
            }
        }
    }

    Err(anyhow::anyhow!("Could not resolve hostname for {}", ip))
}

fn extract_ip_from_line(line: &str) -> Option<String> {
    // Parse line like "Nmap scan report for 192.168.1.100"
    if let Some(ip_part) = line.split_whitespace().last() {
        if ip_part.contains('.') && ip_part.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Some(ip_part.to_string());
        }
    }
    None
}

async fn get_monitoring_status() -> Result<serde_json::Value> {
    let state_path = "/data/state.json";

    match tokio::fs::read_to_string(state_path).await {
        Ok(state_content) => {
            let state: serde_json::Value = serde_json::from_str(&state_content)?;
            Ok(serde_json::json!({
                "status": "active",
                "monitoring_state": state,
                "last_updated": chrono::Utc::now()
            }))
        }
        Err(_) => Ok(serde_json::json!({
            "status": "initializing",
            "message": "No monitoring data available yet"
        })),
    }
}

async fn handle_sms_response() -> Result<()> {
    info!("Handling SMS response...");

    let mut state = load_monitoring_state().await?;

    // Mark the most recent active alert as responded
    if let Some(alert) = state
        .alerts
        .iter_mut()
        .filter(|a| a.is_active)
        .max_by_key(|a| a.sent_at)
    {
        alert.responded_at = Some(Utc::now());
        alert.is_active = false;

        info!("Marked alert {} as responded", alert.id);
    }

    save_monitoring_state(&state).await?;
    Ok(())
}

async fn init_monitoring() -> Result<()> {
    info!("Initializing monitoring system...");

    // Create initial empty state
    let state = MonitoringState::default();
    save_monitoring_state(&state).await?;

    info!("Monitoring system initialized");
    Ok(())
}

// Configuration and state management
async fn load_config() -> Result<Config> {
    let config_path =
        env::var("CONFIG_PATH").unwrap_or_else(|_| "/etc/config/config.yaml".to_string());
    let config_content = tokio::fs::read_to_string(&config_path).await?;
    let config: Config = serde_yaml::from_str(&config_content)?;
    Ok(config)
}

async fn load_monitoring_state() -> Result<MonitoringState> {
    let state_path = "/data/state.json";

    match tokio::fs::read_to_string(state_path).await {
        Ok(state_content) => {
            let state: MonitoringState = serde_json::from_str(&state_content)?;
            Ok(state)
        }
        Err(_) => {
            // State file doesn't exist yet, return default
            Ok(MonitoringState::default())
        }
    }
}

async fn save_monitoring_state(state: &MonitoringState) -> Result<()> {
    let state_path = "/data/state.json";
    let state_json = serde_json::to_string_pretty(state)?;

    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(state_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(state_path, state_json).await?;
    info!("Saved monitoring state to {}", state_path);

    Ok(())
}
