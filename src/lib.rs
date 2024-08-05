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
use std::{fmt, net::IpAddr, num::ParseIntError, process, time::Duration};
use threading::ThreadPool;

pub mod threading;

/* ---[Argument Structure]---*/
/* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
*  Arguments with no default value are considered required.*/
#[derive(Parser, Debug)]
#[command(version, about)]
/// A simple syn port scanner in rust
pub struct Args {
    #[arg(short, long, num_args = 1.., value_delimiter = ' ')]
    pub targets: Vec<IpAddr>,

    #[arg(short, long, value_parser = port_parser, num_args = 1.., value_delimiter = ' ')]
    pub ports: Vec<Vec<u16>>,

    #[arg(short, long)]
    pub interface: Option<String>,
}

fn port_parser(s: &str) -> Result<Vec<u16>, ParseIntError> {
    if s.contains('-') {
        /* For parsing port range (like 80-220) */
        let mut parts = s.split('-');

        let first: u16 = parts.next().unwrap().parse()?;
        let last: u16 = parts.next().unwrap().parse()?;

        Ok((first..last).collect())
    } else {
        let port = s.parse::<u16>();

        match port {
            Ok(port) => Ok(vec![port]),
            Err(e) => Err(e),
        }
    }
}

/*---[Result enum]---*/
pub enum PortState {
    Opened,
    Closed,
    Filtered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortState::Opened => write!(f, "opened"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
        }
    }
}

/*---[Config structures]---*/
#[derive(Clone)]
pub struct IpConfig {
    pub target: IpAddr,
    pub source: IpAddr,
}

pub struct PortConfig {
    pub target: u16,
    pub source: u16,
}

pub fn run_syn_scan(target_ips: Vec<IpAddr>, target_ports: Vec<u16>, interface: &NetworkInterface) {
    /* for the source port generation */
    let mut rng = thread_rng();

    let pool = ThreadPool::new(4);

    for target_ip in target_ips {
        let ip_config = IpConfig {
            target: target_ip,
            source: get_source_ip(interface, target_ip.is_ipv4()),
        };

        for target_port in &target_ports {
            let ip_config = ip_config.clone();
            let port_config = PortConfig {
                target: *target_port,
                source: rng.gen_range(1024..65535),
            };

            pool.execute(move || {
                syn_scan(&ip_config, &port_config);
            });
        }
    }
}

pub fn syn_scan(ip_config: &IpConfig, port_config: &PortConfig) {
    let mut result = PortState::Closed;

    /*Create the tcp packet*/
    let mut syn_buffer = [0; 20];
    let syn_packet = build_packet(&mut syn_buffer, ip_config, port_config).consume_to_immutable();

    /*---[Transport channel creation]---*/
    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, ip_config.target).unwrap();

    /*---[Packet receiving]---*/
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        match iter.next_with_timeout(Duration::from_secs(5)) {
            Ok(None) => {
                result = PortState::Filtered;
                break;
            }
            Ok(Some((packet, addr))) => {
                if addr == ip_config.target && packet.get_source() == port_config.target {
                    /* Check if RST is not set */
                    if packet.get_flags() & 0b00000100 == 0 {
                        result = PortState::Opened;
                    }
                    break;
                }
            }
            Err(e) => println!("error reading packet : {}", e),
        }
    }

    let target = format!("{}:{}", ip_config.target, port_config.target);
    println!("{target} : {result} ");
}

pub fn get_source_ip(interface: &NetworkInterface, is_v4: bool) -> IpAddr {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) if is_v4 => {
                Some(IpAddr::V4(addr))
            }
            IpAddr::V6(addr) if !is_v4 => {
                Some(IpAddr::V6(addr))
            }
            _ => None
        }).unwrap_or_else(|| {
            eprintln!(
                "Could not find any ip address for the network interface {} whos type matches with the target ip",
                interface.name
            );
            process::exit(1);})
}

fn build_packet<'a>(
    buffer: &'a mut [u8],
    ip_config: &IpConfig,
    port_config: &PortConfig,
) -> MutableTcpPacket<'a> {
    /*---[TCP packet structure]---*/
    let packet = Tcp {
        /* (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure) */
        source: port_config.source,
        destination: port_config.target,
        sequence: 0,
        acknowledgement: 0,
        data_offset: 5, // we have no options, so we can reduce the offset to the maximum
        reserved: 0,
        flags: 0b00000010, // SYN flag
        window: 0,
        checksum: 0, // set after
        urgent_ptr: 0,
        options: Vec::new(),
        payload: Vec::new(),
    };

    /*---[On the wire TCP packet]---*/
    assert!(buffer.len() >= 20);
    let mut tcp_packet = MutableTcpPacket::new(buffer).unwrap();

    tcp_packet.populate(&packet);

    let checksum = match (ip_config.source, ip_config.target) {
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
        /*---[Interface name supplied]---*/
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

        /*---[No interface name supplied]---*/
        None => {
            println!("No interface specified, trying to get the default one");

            /*Try to find an interface that is up, isn't loopback and as an ip.
             * If more than one interface could work, just takes the first one.*/
            let interface = all_interfaces
                .iter()
                .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
                .unwrap_or_else(|| {
                    eprintln!("Could not find any up network interface that has an IP");
                    process::exit(1);
                });

            println!("Got network interface : {}", interface.name);

            interface.to_owned()
        }
    }
}

#[cfg(test)]
mod tests;
