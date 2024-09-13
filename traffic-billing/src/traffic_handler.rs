use crate::TRAFFIC_BILLING_COUNTER_VEC;
use dashmap::DashMap;
use log::info;
use std::{net::Ipv4Addr, sync::Arc};
use traffic_billing_common::PacketLog;
use crate::pod_watcher::PodInfo;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn from_char(c: char) -> Option<Self> {
        match c {
            'I' => Some(Direction::Inbound),
            'O' => Some(Direction::Outbound),
            _ => None,
        }
    }
}

pub fn handle_traffic_event(data: &PacketLog, pod_map: &Arc<DashMap<String, PodInfo>>) {
    let src_addr = Ipv4Addr::from(data.saddr);
    let dst_addr = Ipv4Addr::from(data.daddr);

    let direction = Direction::from_char(data.direction)
        .expect("Invalid direction character");

    let (traffic_direction, pod_addr, metric_direction) = match direction {
        Direction::Outbound => ("Outbound", src_addr, "outbound"),
        Direction::Inbound => ("Inbound", dst_addr, "inbound"),
    };

    let pod_info = pod_map.get(&pod_addr.to_string());
    let (pod_name, pod_namespace) = pod_info
        .map(|p| (p.pod_name.clone(), p.namespace.clone()))
        .unwrap_or_else(|| (String::new(), String::new()));

    let command = String::from_utf8_lossy(&data.command);

    info!(
        "{} traffic: Source IP: {}, Destination IP: {}, Packet size: {} bytes, PID: {}, Command: {}",
        traffic_direction, src_addr, dst_addr, data.len, data.pid, command
    );

    TRAFFIC_BILLING_COUNTER_VEC
        .with_label_values(&[
            &src_addr.to_string(),
            &dst_addr.to_string(),
            metric_direction,
            &data.pid.to_string(),
            &command,
            &pod_name,
            &pod_namespace,
        ])
        .inc_by(data.len as f64);
}