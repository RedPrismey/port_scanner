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
use std::error::Error;
use std::net::IpAddr;
use std::process;

/* ---[Argument Structure]---*/
/* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
* The arguments with no default value are considered required.*/
#[derive(Parser, Debug)]
#[command(version, about)]
/// A simple syn port scanner in rust
pub struct Args {
    #[arg(short, long)]
    pub target: String,

    #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    pub ports: Vec<u16>,

    #[arg(short, long, default_value = "default_interface")]
    pub interface: String,
}

/*---[Config structure]---*/
/* Used to store the arguments we'll be passing arround a lot, like target port and target ip*/
pub struct Config {
    pub target_ip: IpAddr,
    pub target_ports: Vec<u16>,
    pub source_ip: IpAddr,
}

impl Config {
    pub fn build(args: Args) -> Result<Config, Box<dyn Error>> {
        let target_ip = args.target;
        let target_ports = args.ports;
        let interface_name = args.interface;

        /* Parse target into IpAddr */
        //TODO: Allow user to specify range of port or addresses
        let target_ip: IpAddr = target_ip.parse()?;

        let interface = get_interface(interface_name);

        /* Get supplied interface's ip with the same type as the target address */
        let source_ip = get_source_ip(&interface, target_ip.is_ipv4());

        Ok(Config {
            target_ip,
            target_ports,
            source_ip,
        })
    }
}

pub fn run_syn_scan(config: &Config) -> Vec<bool> {
    let mut result = Vec::new();

    for port in config.target_ports.iter() {
        result.push(syn_scan(config, port));
    }

    result
}

pub fn syn_scan(config: &Config, target_port: &u16) -> bool {
    let mut opened = false;

    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(1024..65535);

    /*Create the tcp packet*/
    let mut syn_buffer = [0u8; 20];
    let syn_packet = build_packet(&mut syn_buffer, config, target_port, source_port, true)
        .consume_to_immutable();

    println!("syn packet : {:#?}\n\n", syn_packet);

    /*---[Transport channel creation]---*/
    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, config.target_ip).unwrap();

    /*---[Packet receiving]---*/
    let mut iter = tcp_packet_iter(&mut rx);
    //TODO: add a timeout
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                /*Checks if the packet is the response to our packet*/
                if addr == config.target_ip && packet.get_source() == *target_port {
                    println!("packet : {:#?}, addr : {:#?}\n", packet, addr);
                    /*Check if RST is set*/
                    if packet.get_flags() & 0b00000100 == 0 {
                        /*If no RST, the port is opened*/
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
        let rst_packet = build_packet(&mut rst_buffer, config, target_port, source_port, false)
            .consume_to_immutable();

        tx.send_to(rst_packet, config.target_ip).unwrap();
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
    config: &Config,
    target_port: &u16,
    source_port: u16,
    syn: bool,
) -> MutableTcpPacket<'a> {
    /*---[TCP packet structure]---*/
    let packet = Tcp {
        /* (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure) */
        source: source_port,
        destination: *target_port,
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

    let checksum = match (config.source_ip, config.target_ip) {
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

fn get_interface(interface_name: String) -> NetworkInterface {
    let all_interfaces = interfaces();

    if interface_name != "default_interface" {
        let interface_opt: Option<&NetworkInterface> =
            all_interfaces.iter().find(|e| e.name == interface_name);

        let interface: NetworkInterface = match interface_opt {
            Some(interface) => interface.to_owned(),
            None => {
                eprintln!("Interface {} not found", interface_name);
                process::exit(1)
            }
        };

        println!("Got network interface : {}", interface.name);

        interface
    } else {
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
