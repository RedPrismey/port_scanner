use clap::Parser;
use core::panic;
use pnet::{
    datalink::{interfaces, NetworkInterface},
    packet::{
        ip::IpNextHeaderProtocols::Tcp,
        tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, Tcp},
    },
    transport::{
        tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
    },
};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::process;
use std::{net::IpAddr, num::ParseIntError};

/* ---[Argument Structure]---*/
/* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
*  The arguments with no default value are considered required.*/
#[derive(Parser, Debug)]
#[command(version, about)]
/// A simple syn port scanner in rust
pub struct Args {
    #[arg(short, long, num_args = 1.., value_delimiter = ' ')]
    pub targets: Vec<IpAddr>,

    #[arg(short,long,  value_parser = port_parser, num_args = 1.., value_delimiter = ' ')]
    pub ports: Vec<Vec<u16>>,

    #[arg(short, long)]
    pub interface: Option<String>,
}

fn port_parser(s: &str) -> Result<Vec<u16>, ParseIntError> {
    if s.contains('-') {
        let mut parts = s.split('-');

        let first = match parts.next().unwrap().parse::<u16>() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let last = match parts.next().unwrap().parse::<u16>() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        Ok((first..last).collect())
    } else {
        let parse = s.parse::<u16>();
        match parse {
            Ok(port) => Ok(vec![port]),
            Err(e) => Err(e),
        }
    }
}

/*---[Config structures]---*/
pub struct IpConfig {
    pub target_ip: IpAddr,
    pub source_ip: IpAddr,
}

pub struct PortConfig {
    pub target_port: u16,
    pub source_port: u16,
}

pub fn run_syn_scan(
    target_ips: Vec<IpAddr>,
    target_ports: Vec<u16>,
    interface: &NetworkInterface,
) -> HashMap<String, bool> {
    let mut results = HashMap::new();
    let mut rng = thread_rng();

    for target_ip in target_ips {
        let source_ip = get_source_ip(interface, target_ip.is_ipv4());

        let ip_config = IpConfig {
            target_ip,
            source_ip,
        };

        for target_port in &target_ports {
            let source_port: u16 = rng.gen_range(1024..65535);

            let port_config = PortConfig {
                target_port: *target_port,
                source_port,
            };

            let target = format!("{}:{}", target_ip, target_port);
            let result = syn_scan(&ip_config, &port_config);
            println!("{target} : {result} ");

            results.insert(target, result);
        }
    }

    results
}

pub fn syn_scan(ip_config: &IpConfig, port_config: &PortConfig) -> bool {
    let mut opened = false;

    /*Create the tcp packet*/
    let mut syn_buffer = [0u8; 20];
    let syn_packet =
        build_packet(&mut syn_buffer, ip_config, port_config, true).consume_to_immutable();

    /*---[Transport channel creation]---*/
    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, ip_config.target_ip).unwrap();

    /*---[Packet receiving]---*/
    let mut iter = tcp_packet_iter(&mut rx);
    //TODO: add a timeout
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if addr == ip_config.target_ip && packet.get_source() == port_config.target_port {
                    /* Check if RST is set */
                    if packet.get_flags() & 0b00000100 == 0 {
                        opened = true;
                    }

                    break;
                }
            }
            Err(e) => println!("error reading packet : {}", e),
        }
    }

    /*---[Connection closing]---*/
    /* If target port didn't try to connect back, we don't need to do anything*/
    if opened {
        println!("sending RST packet");

        let mut rst_buffer = [0u8; 20];
        let rst_packet =
            build_packet(&mut rst_buffer, ip_config, port_config, false).consume_to_immutable();

        tx.send_to(rst_packet, ip_config.target_ip).unwrap();
    }

    opened
}

fn get_source_ip(interface: &NetworkInterface, v4: bool) -> IpAddr {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) => {
                match v4 {
                    true => Some(IpAddr::V4(addr)),
                    false => None,
                }
            }
            IpAddr::V6(addr) => {
                match !v4 {
                    true => Some(IpAddr::V6(addr)),
                    false => None,
                }
            }
        })
        .unwrap_or_else(|| {
            eprintln!(
                "Could not find any ip address for the network interface {} whos type matches with the target ip",
                interface.name
            );
            process::exit(1);
        })
}

fn build_packet<'a>(
    buffer: &'a mut [u8],
    ip_config: &IpConfig,
    port_config: &PortConfig,
    syn: bool,
) -> MutableTcpPacket<'a> {
    /*---[TCP packet structure]---*/
    let packet = Tcp {
        /* (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure) */
        source: port_config.source_port,
        destination: port_config.target_port,
        sequence: 0,
        acknowledgement: 0,
        data_offset: 5, // we have no options, so we can reduce the offset to the maximum
        reserved: 0,
        flags: if syn {
            0b00000010 // SYN flag
        } else {
            0b00000100 // RST flag
        },
        window: 0,
        checksum: 0, // set after
        urgent_ptr: 0,
        options: Vec::new(),
        payload: Vec::new(),
    };

    /*---[On the wire TCP packet]---*/
    let mut tcp_packet = MutableTcpPacket::new(buffer).unwrap();

    tcp_packet.populate(&packet);

    let checksum = match (ip_config.source_ip, ip_config.target_ip) {
        (IpAddr::V4(src), IpAddr::V4(target)) => {
            ipv4_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        (IpAddr::V6(src), IpAddr::V6(target)) => {
            ipv6_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        _ => {
            eprintln!("Can't calculate checksum for two different type of ip addresses");
            process::exit(1);
        }
    };
    tcp_packet.set_checksum(checksum);

    tcp_packet
}

pub fn get_interface(interface_name: Option<String>) -> NetworkInterface {
    let all_interfaces = interfaces();

    match interface_name {
        Some(name) => {
            let interface_opt: Option<&NetworkInterface> =
                all_interfaces.iter().find(|e| e.name == name);

            let interface: NetworkInterface = match interface_opt {
                Some(interface) => interface.to_owned(),
                None => {
                    eprintln!("Interface {} not found", name);
                    process::exit(1)
                }
            };

            println!("Got network interface : {}", interface.name);

            interface
        }
        None => {
            println!("No interface specified, trying to get the default one");

            /*Try to find an interface that is up, isn't loopback and as an ip.
             * If more than one interface could work, just takes the first one.*/
            let interface_opt: Option<&NetworkInterface> = all_interfaces
                .iter()
                .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

            let interface: NetworkInterface = match interface_opt {
                Some(interface) => interface.to_owned(),
                None => {
                    eprintln!("Could not find any up network interface that has an IP");
                    process::exit(1);
                }
            };

            println!("Got network interface : {}", interface.name);

            interface
        }
    }
}
