use super::*;
use pnet::{
    datalink::NetworkInterface,
    ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network},
};
use std::sync::mpsc::channel;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use threading::ThreadPool;

#[test]
fn threads() {
    let pool = ThreadPool::new(4);
    let (tx, rx) = channel();
    let target_ports: Vec<u16> = (80..84).collect();
    let target_ips = [IpAddr::V4(Ipv4Addr::new(192, 168, 96, 21))];
    let interface = &get_interface(None);

    let mut rng = thread_rng();

    for target_port in &target_ports {
        let tx = tx.clone();

        let ip_config = IpConfig {
            target: target_ips[0],
            source: get_source_ip(interface, target_ips[0].is_ipv4()),
        };

        let port_config = PortConfig {
            target: *target_port,
            source: rng.gen_range(1024..65535),
        };

        pool.execute(move || {
            syn_scan(&ip_config, &port_config);
            tx.send("a").unwrap();
        });

        match rx.recv_timeout(Duration::from_millis(1500)) {
            Ok(_) => println!("ok"),
            Err(_) => println!("timeout"),
        }
    }
}

#[test]
fn source_ip_v4() {
    let is_v4 = true;
    let ips = vec![
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 0).unwrap()),
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap()),
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 2), 0).unwrap()),
    ];

    let interface = NetworkInterface {
        name: String::from("Test"),
        description: String::from("Test"),
        index: 0,
        mac: None,
        ips,
        flags: 0,
    };

    let ip = get_source_ip(&interface, is_v4);
    assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 1));
}

#[test]
fn source_ip_v6() {
    let is_v4 = false;
    let ips = vec![
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 0).unwrap()),
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 2), 0).unwrap()),
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 1, 0, 0, 0, 0, 0, 1), 0).unwrap()),
    ];

    let interface = NetworkInterface {
        name: String::from("Test"),
        description: String::from("Test"),
        index: 0,
        mac: None,
        ips,
        flags: 0,
    };

    let ip = get_source_ip(&interface, is_v4);
    assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
}
