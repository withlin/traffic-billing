use dashmap::DashMap;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams},
    runtime::watcher::{watcher, Event},
    Client,
};
use log::{error, info};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PodInfo {
    pub pod_name: String,
    pub namespace: String,
}

// This struct represents the minimal information we need from a Pod
#[derive(Clone)]
struct MinimalPod {
    ip: Option<String>,
    name: Option<String>,
    namespace: Option<String>,
}

impl MinimalPod {
    fn from_pod(pod: Pod) -> Self {
        MinimalPod {
            ip: pod.status.and_then(|s| s.pod_ip),
            name: pod.metadata.name,
            namespace: pod.metadata.namespace,
        }
    }
}

async fn handle_pod_event(pod_map: &DashMap<String, PodInfo>, event: Event<MinimalPod>) {
    match event {
        Event::Applied(pod) => {
            if let (Some(pod_ip), Some(pod_name), Some(namespace)) =
                (pod.ip, pod.name, pod.namespace)
            {
                pod_map.insert(
                    pod_ip.clone(),
                    PodInfo {
                        pod_name: pod_name.clone(),
                        namespace: namespace.clone(),
                    },
                );
                info!("Pod added: {} in namespace {}", pod_name, namespace);
            }
        }
        Event::Deleted(pod) => {
            if let Some(pod_ip) = pod.ip {
                if let Some((_, pod_info)) = pod_map.remove(&pod_ip) {
                    info!(
                        "Pod removed: {} in namespace {}",
                        pod_info.pod_name, pod_info.namespace
                    );
                }
            }
        }
        _ => {}
    }
}

pub async fn watch_pods(client: Client, pod_map: Arc<DashMap<String, PodInfo>>) {
    let api = Api::<Pod>::all(client);
    let lp = ListParams::default();

    info!("Starting to watch pods");

    let watcher = watcher(api, lp).boxed();
    watcher
        .try_for_each(|event| async {
            let minimal_event = match event {
                Event::Applied(pod) => Event::Applied(MinimalPod::from_pod(pod)),
                Event::Deleted(pod) => Event::Deleted(MinimalPod::from_pod(pod)),
                Event::Restarted(pods) => {
                    Event::Restarted(pods.into_iter().map(MinimalPod::from_pod).collect())
                }
            };
            handle_pod_event(&pod_map, minimal_event).await;
            Ok(())
        })
        .await
        .unwrap_or_else(|e| error!("Pod watcher error: {}", e));
}
