use clap::Parser;

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
use std::net::IpAddr;

use core::panic;

use rand::{thread_rng, Rng};

/* ---[Argument Structure]---*/
/* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
* The arguments with no default value are considered required.*/
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(short, long)]
    port: String,

    #[arg(short, long, default_value = "default_interface")]
    interface: String,

    #[arg(long, default_value_t = 5)]
    timeout: u8,
}

/*---[Config structure]---*/
/* Used to store the arguments we'll be passing arround a lot, like target port and target ip*/
pub struct Config {
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub source_ip: IpAddr,
}

impl Config {
    pub fn build(args: Args) -> Config {
        let target_ip = args.target;
        let target_port = args.port;
        let interface_name = args.interface;

        /*Parse port and target into u16 and IpAddr*/
        //TODO: better error handling
        let target_port: u16 = target_port.trim().parse().unwrap();
        let target_ip: IpAddr = target_ip.parse().unwrap();

        let interface = get_interface(interface_name);

        /*Get supplied interface's ip with the same type as the target address*/
        let source_ip = match target_ip {
            IpAddr::V4(_) => interface.ips[0].ip(),
            IpAddr::V6(_) => interface.ips[1].ip(),
        };

        Config {
            target_ip,
            target_port,
            source_ip,
        }
    }
}

pub fn syn_scan(config: &Config) -> bool {
    let mut opened = false;

    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(1024..65535);

    /*Create the tcp packet*/
    let mut syn_buffer = [0u8; 20];
    let syn_packet =
        build_packet(&mut syn_buffer, config, source_port, true).consume_to_immutable();

    println!("syn packet : {:#?}\n\n", syn_packet);

    /*---[Communication with the target]---*/
    /*Creating the transport channels*/
    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, config.target_ip).unwrap();

    /*Recieving packets until we find a response of the target*/
    let mut iter = tcp_packet_iter(&mut rx);
    //TODO: add a timeout
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                /*Checks if the packet is the response to our packet*/
                if addr == config.target_ip && packet.get_source() == config.target_port {
                    println!("packet : {:#?}, addr : {:#?}\n", packet, addr);
                    /*Check if RST is set*/
                    if packet.get_flags() & 0b00000100 == 0 {
                        /*If no RST, the port is opened*/
                        opened = true;
                    }

                    break;
                }
            }
            Err(e) => panic!("error reading packet : {}", e),
        }
    }

    if opened {
        /*Closing the communication if the port is open*/
        println!("sending RST packet");

        let mut rst_buffer = [0u8; 20];
        let rst_packet =
            build_packet(&mut rst_buffer, config, source_port, false).consume_to_immutable();

        tx.send_to(rst_packet, config.target_ip).unwrap();
    }

    opened
}

fn build_packet<'a>(
    buffer: &'a mut [u8],
    config: &Config,
    source_port: u16,
    syn: bool,
) -> MutableTcpPacket<'a> {
    /*Filling most of the tcp packet fields*/
    let packet = Tcp {
        /*(https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)*/
        source: source_port,
        destination: config.target_port,
        sequence: 0,
        acknowledgement: 0,
        data_offset: 5, // we have no options, so we can reduce the offset to the maximum
        reserved: 0,
        flags: if syn {
            0b00000010 // syn flag
        } else {
            0b00000100
        },
        window: 0,
        checksum: 0, // we'll set it after
        urgent_ptr: 0,
        options: Vec::new(),
        payload: Vec::new(),
    };

    /*Creating the MutableTcpPacket (the one we'll be sending)*/
    let mut tcp_packet = match MutableTcpPacket::new(buffer) {
        Some(packet) => packet,
        None => panic!("Error building packet : buffer is too small"),
    };

    tcp_packet.populate(&packet);

    let checksum = match (config.source_ip, config.target_ip) {
        (IpAddr::V4(src), IpAddr::V4(target)) => {
            ipv4_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        (IpAddr::V6(src), IpAddr::V6(target)) => {
            ipv6_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        _ => panic!("Can't calculate checksum for two different type of ip addresses"),
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
            None => panic!("Interface not found : {}", interface_name),
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
            None => panic!("Could not find any network interface that are up and have an IP"),
        };

        println!("Got network interface : {}", interface.name);

        interface
    }
}
