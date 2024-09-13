use aya::{
    include_bytes_aligned,
    maps::{lpm_trie::LpmTrie, perf::AsyncPerfEventArray},
    programs::KProbe,
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use dashmap::DashMap;
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use kube::{
    Client,
};
use lazy_static::lazy_static;
use log::{error, info};
use prometheus::{register_counter_vec, CounterVec, Encoder, TextEncoder};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::{
    env, 
    convert::{Infallible, TryInto},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{signal, task};
use traffic_billing_common::PacketLog;

mod pod_watcher;
mod traffic_handler;

use pod_watcher::PodInfo;
use traffic_handler::handle_traffic_event;

lazy_static! {
    static ref TRAFFIC_BILLING_COUNTER_VEC: CounterVec = register_counter_vec!(
        "traffic_billing_bytes_total",
        "Traffic billing bytes total.",
        &[
            "src_ip",
            "dst_ip",
            "direction",
            "pid",
            "command",
            "pod_name",
            "namespace",
            "cluster_name"
        ]
    )
    .unwrap();
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "3000")]
    port: u16,
    
    #[clap(long, use_value_delimiter = true, value_delimiter = ',')]
    cidrs: Vec<String>,

    #[clap(long)]
    cluster_name: String,
}

async fn metrics(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            Ok(Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(buffer))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()),
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let node_ip = env::var("NODE_IP").map_err(|e| {
        error!("NODE_IP environment variable not set");
        e
    })?;

    if node_ip.is_empty() {
        error!("NODE_IP environment variable is empty");
        return Err(anyhow::anyhow!("NODE_IP environment variable is empty"));
    }

    let pod_map = Arc::new(DashMap::new());

    let client = Client::try_default().await?;
    task::spawn(pod_watcher::watch_pods(
        client, 
        Arc::clone(&pod_map),
        opt.cluster_name.clone(),
        node_ip));

    let addr: SocketAddr = format!("0.0.0.0:{}", opt.port).parse()?;
    let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(metrics)) });
    let server = Server::bind(&addr).serve(make_svc);

    let mut bpf = load_bpf()?;
    BpfLogger::init(&mut bpf)?;

    attach_kprobes(&mut bpf)?;
    setup_lpm_trie(&mut bpf, &opt.cidrs)?;

    let _perf_array = setup_perf_array(&mut bpf, pod_map)?;

    info!("Server is starting on {}", addr);
    let server_task = task::spawn(async move {
        if let Err(e) = server.await {
            error!("Server error: {}", e);
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    server_task.abort();
    Ok(())
}



fn load_bpf() -> Result<Bpf, anyhow::Error> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/traffic-billing"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/traffic-billing"
    ))?;
    Ok(bpf)
}

fn attach_kprobes(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let kprobes = [
        "ip_send_skb",
        "skb_consume_udp",
        "tcp_sendmsg",
        "tcp_cleanup_rbuf",
    ];

    for probe in kprobes.iter() {
        let program: &mut KProbe = bpf.program_mut(probe).unwrap().try_into()?;
        program.load()?;
        program.attach(probe, 0)?;
    }

    Ok(())
}

fn setup_lpm_trie(bpf: &mut Bpf, cidrs: &[String]) -> Result<(), anyhow::Error> {
    let  trie = LpmTrie::try_from(bpf.map_mut("LANCIDRS")?)?;

    for (i, cidr) in cidrs.iter().enumerate() {
        let (ip, prefix_len) = parse_cidr(cidr)?;
        let key = aya::maps::lpm_trie::Key::new(prefix_len, u32::from(ip).to_be());
        trie.insert(&key, (i + 1) as u32, 0)?;
    }

    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), anyhow::Error> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid CIDR format"));
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    Ok((ip, prefix_len))
}

fn setup_perf_array(
    bpf: &mut Bpf,
    pod_map: Arc<DashMap<String, PodInfo>>,
) -> Result<(), anyhow::Error> {
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let pod_map_clone = Arc::clone(&pod_map);

        task::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let data =
                                unsafe { buffers[i].as_ptr().cast::<PacketLog>().read_unaligned() };
                            handle_traffic_event(&data, &pod_map_clone);
                        }
                    }
                    Err(e) => error!("Error reading events: {}", e),
                }
            }
        });
    }

    Ok(())
}
