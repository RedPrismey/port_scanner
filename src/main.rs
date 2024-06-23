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
    mut buffer: &mut [u8],
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
) -> MutableTcpPacket {
    let packet = Tcp {
        /*(https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)*/
        source: source_port,
        destination: target_port,
        sequence: 0,
        acknowledgement: 0,
        data_offset: 5, // we have no options, so we can reduce the offset to the maximum
        reserved: 0,
        flags: 0b00000010, // syn flag
        window: 0,
        checksum: 0, // we'll set it after
        urgent_ptr: 0,
        options: Vec::new(),
        payload: Vec::new(),
    };

    let mut tcp_packet = MutableTcpPacket::new(buffer).unwrap();

    tcp_packet.populate(&packet);

    let checksum = match (source_ip, target_ip) {
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

fn syn_scan(interface: &NetworkInterface, target_ip: IpAddr, target_port: u16) {
    /*Get supplied interface's ip*/
    let source_ip = interface.ips[0].ip();

    /*Generate the source port*/
    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(1024..65535);

    /*Create the tcp packet*/
    let mut buffer = [0u8; 128];

    let syn_packet = build_packet(&mut buffer, source_ip, target_ip, source_port, target_port)
        .consume_to_immutable();

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
