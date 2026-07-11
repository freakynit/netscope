use anyhow::Result;
use clap::{Parser, Subcommand};
use netscope::{
    capture::{self, RawCaptureOptions},
    certs::{self, CaPaths},
    events::TrafficFilter,
    hooks::{AllowAll, SharedHookEngine, WebSocketHookEngine, WebSocketHookOptions},
    proxy::{self, ProxyOptions},
    store::EventStore,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(name = "netscope", about = "macOS network inspection core")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Proxy {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long)]
        mitm: bool,
        #[arg(long, default_value = ".netscope")]
        ca_dir: PathBuf,
        #[arg(long)]
        events: Option<PathBuf>,
        /// Loopback WebSocket address for language-neutral local hooks.
        #[arg(long)]
        hook_listen: Option<SocketAddr>,
        #[arg(long, default_value_t = 250)]
        hook_timeout_ms: u64,
        #[arg(long, default_value_t = 1_048_576)]
        hook_max_json_body_bytes: usize,
    },
    Capture {
        /// Repeat to capture multiple interfaces, e.g. --interface en0 --interface lo0.
        #[arg(long, required = true)]
        interface: Vec<String>,
        #[arg(long)]
        protocol: Vec<String>,
        #[arg(long)]
        port: Vec<u16>,
        #[arg(long)]
        ip: Vec<std::net::IpAddr>,
        #[arg(long)]
        hostname: Vec<String>,
        /// Present in the filter contract; passive process attribution is not available yet.
        #[arg(long)]
        process: Option<String>,
        #[arg(long)]
        events: Option<PathBuf>,
        /// Write raw link-layer frames to rotating pcapng files. With multiple interfaces,
        /// the interface name is inserted into the filename.
        #[arg(long)]
        pcapng: Option<PathBuf>,
        #[arg(long, default_value_t = 128)]
        pcapng_rotate_mb: u64,
    },
    Cert {
        #[command(subcommand)]
        command: CertCommand,
    },
    Interfaces,
}
#[derive(Subcommand)]
enum CertCommand {
    Generate {
        #[arg(long, default_value = ".netscope")]
        ca_dir: PathBuf,
    },
    Install {
        #[arg(long, default_value = ".netscope")]
        ca_dir: PathBuf,
    },
    Remove {
        #[arg(long, default_value = ".netscope")]
        ca_dir: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("netscope=info")
        .init();
    match Cli::parse().command {
        Command::Proxy {
            listen,
            mitm,
            ca_dir,
            events,
            hook_listen,
            hook_timeout_ms,
            hook_max_json_body_bytes,
        } => {
            let store = EventStore::new(events).await?;
            let hooks: SharedHookEngine = match hook_listen {
                Some(listen) => {
                    WebSocketHookEngine::bind(WebSocketHookOptions {
                        listen,
                        timeout: std::time::Duration::from_millis(hook_timeout_ms),
                        max_json_body_bytes: hook_max_json_body_bytes,
                    })
                    .await?
                }
                None => Arc::new(AllowAll),
            };
            proxy::run(ProxyOptions {
                listen,
                mitm,
                ca: Some(CaPaths::in_dir(ca_dir)),
                hooks,
                store,
                max_hook_json_body_bytes: hook_max_json_body_bytes,
            })
            .await
        }
        Command::Capture {
            interface,
            protocol,
            port,
            ip,
            hostname,
            process,
            events,
            pcapng,
            pcapng_rotate_mb,
        } => {
            capture::run_interfaces(
                interface,
                TrafficFilter {
                    protocols: protocol,
                    ports: port,
                    ips: ip,
                    hostnames: hostname,
                    process,
                    ..Default::default()
                },
                EventStore::new(events).await?,
                pcapng.map(|path| RawCaptureOptions {
                    path,
                    rotate_bytes: pcapng_rotate_mb.saturating_mul(1024 * 1024),
                }),
            )
            .await
        }
        Command::Cert { command } => match command {
            CertCommand::Generate { ca_dir } => certs::generate_ca(&CaPaths::in_dir(ca_dir)),
            CertCommand::Install { ca_dir } => certs::install_ca(&CaPaths::in_dir(ca_dir)),
            CertCommand::Remove { ca_dir } => certs::remove_ca(&CaPaths::in_dir(ca_dir)),
        },
        Command::Interfaces => {
            #[cfg(feature = "capture")]
            {
                for d in pcap::Device::list()? {
                    println!("{}", d.name);
                }
                Ok(())
            }
            #[cfg(not(feature = "capture"))]
            {
                Err(anyhow::anyhow!("built without packet capture support"))
            }
        }
    }
}
