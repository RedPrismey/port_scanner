use clap::Parser;

use pnet::datalink::{interfaces, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols::Tcp;
use pnet::packet::tcp::{MutableTcpPacket, Tcp};
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4};
use pnet::util::ipv4_checksum;

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

fn syn_scan(interface: &NetworkInterface, target_ip: IpAddr, target_port: u16) {
    /*---[Create the syn tcp package]---*/
    /*Get supplied interface's ip*/
    let source_ip = match interface.ips[0].ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => panic!("Source ip is ipv6, wich is not yet supported (ip : {})", ip),
    };

    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(1024..65535);

    let packet = match target_ip {
        IpAddr::V4(target_ip) => {
            Tcp {
                /*(https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)*/
                source: source_port,
                destination: target_port,
                sequence: 0,
                acknowledgement: 0,
                data_offset: 5, // we have no options, so we can reduce it to the maximum
                reserved: 0,
                flags: 0b00000010, // for the syn flag
                window: 0,
                /*we use the utils function, because it allows us to not yet build a TcpPacket*/
                checksum: ipv4_checksum(&[0], 8, &[0], &source_ip, &target_ip, Tcp),
                urgent_ptr: 0,
                options: Vec::new(),
                payload: Vec::new(),
            }
        }
        IpAddr::V6(ip) => panic!("Source ip is ipv6, wich is not yet supported (ip : {})", ip),
    };

    let mut buffer = [0; 20];
    let mut syn_packet = MutableTcpPacket::new(&mut buffer).unwrap();
    syn_packet.populate(&packet);

    let syn_packet = syn_packet.consume_to_immutable();

    println!("syn packet : {:#?}", syn_packet);

    /*---[Send packet]---*/
    //the recieve buffer size is 4096, I'll see if I need to modify it later or not
    let (mut tx, rx) = match transport_channel(4096, Layer4(Ipv4(Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    tx.send_to(syn_packet, target_ip).unwrap();
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
