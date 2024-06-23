use clap::Parser;

use pnet::{
    datalink::{interfaces, NetworkInterface},
    packet::{
        ip::IpNextHeaderProtocols::Tcp,
        tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, Tcp, TcpFlags, TcpOption},
        MutablePacket,
    },
    transport::{
        tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
    },
    util,
};

use core::panic;

use std::net::IpAddr;

use rand::{thread_rng, Rng};

/* ---[Argument Structure]---*/
/* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
* The arguments with no default value are considered required.*/
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(short, long)]
    port: String,

    #[arg(short, long, default_value = "default_interface")]
    interface: String,
}

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    /*Get args from clap (program arguments)*/
    let target = args.target;
    let port = args.port;
    let interface_name = args.interface;

    /*Parse port and target into u16 and IpAddr*/
    //TODO: better error handling
    let port = port.trim().parse::<u16>().unwrap();
    let ip: IpAddr = target.parse().unwrap();

    /*---[Interface handling]---*/
    /*If no interface name is supplied, try getting a default interface*/
    let interface = get_interface(interface_name);

    println!(
        "Interface : {:#?}\nPort : {}\nIP : {:#?}\n\n",
        interface, port, ip
    );

    syn_scan(&interface, ip, port);
}

fn build_packet(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    syn: bool,
) {
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_data_offset(8);

    if syn {
        tcp_packet.set_flags(TcpFlags::SYN);
    } else {
        tcp_packet.set_flags(TcpFlags::RST);
    }

    let checksum = match (source_ip, target_ip) {
        (IpAddr::V4(src), IpAddr::V4(target)) => {
            ipv4_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        (IpAddr::V6(src), IpAddr::V6(target)) => {
            ipv6_checksum(&tcp_packet.to_immutable(), &src, &target)
        }
        _ => panic!("cant create socket in get_socket"),
    };
    tcp_packet.set_checksum(checksum);
}

fn syn_scan(interface: &NetworkInterface, target_ip: IpAddr, target_port: u16) {
    /*---[Create the syn tcp package]---*/
    /*Get supplied interface's ip*/
    let source_ip = interface.ips[0].ip();

    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(1024..65535);

    let mut buffer = [0; 128];
    let mut syn_packet = MutableTcpPacket::new(&mut buffer).unwrap();

    build_packet(
        &mut syn_packet,
        source_ip,
        target_ip,
        source_port,
        target_port,
        true,
    );

    let syn_packet = syn_packet.consume_to_immutable();

    println!("syn packet : {:#?}\n\n", syn_packet);

    /*---[Send packet]---*/
    //the recieve buffer size is 4096, I'll see if I need to modify it later or not
    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, target_ip).unwrap();

    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => println!("packet : {:#?}, addr : {:#?}\n", packet, addr),
            Err(e) => panic!("error reading packet : {}", e),
        }
    }
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
