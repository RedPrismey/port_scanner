use super::*;
use pnet::{
    datalink::NetworkInterface,
    ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network},
};
use std::net::{Ipv4Addr, Ipv6Addr};

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
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap()),
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

#[test]
fn get_interface_default() {
    let interfaces = vec![
        NetworkInterface {
            name: String::from("No ip"),
            description: String::from("Not the right one"),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 1, // running flag
        },
        NetworkInterface {
            name: String::from("Not up"),
            description: String::from("Not the right one"),
            index: 2,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 0, // not running flag
        },
        NetworkInterface {
            name: String::from("Loopback"),
            description: String::from("Not the right one"),
            index: 2,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 9, // Loopback + running flag
        },
        NetworkInterface {
            name: String::from("Good"),
            description: String::from("The right one"),
            index: 0,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 1,
        },
    ];

    let interface = get_interface(None, interfaces);
    assert_eq!(interface.description, "The right one");
}

#[test]
fn get_interface_choosing() {
    let interfaces = vec![
        NetworkInterface {
            name: String::from("No ip"),
            description: String::from("Not the right one"),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 1, // running flag
        },
        NetworkInterface {
            name: String::from("Not up"),
            description: String::from("Not the right one"),
            index: 2,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 0, // not up flag
        },
        NetworkInterface {
            name: String::from("Loopback"),
            description: String::from("Not the right one"),
            index: 2,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 9, // Loopback + running flag
        },
        NetworkInterface {
            name: String::from("Good"),
            description: String::from("Not the right one"),
            index: 0,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 1,
        },
        NetworkInterface {
            name: String::from("The chosen one"),
            description: String::from("The right one"),
            index: 0,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), 0).unwrap(),
            )],
            flags: 1,
        },
    ];

    let interface = get_interface(Some(String::from("The chosen one")), interfaces);
    assert_eq!(interface.description, "The right one");
}
