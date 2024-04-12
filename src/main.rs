use clap::Parser;
use pnet::datalink::{interfaces, NetworkInterface};

/* ---[Argument Structure]---
*
* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
* The arguments with no default value are considered required.   */

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(short, long)]
    ports: String,

    #[arg(short, long, default_value = "default_interface")]
    interface: String,
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

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    let target = args.target;
    let ports = args.ports;
    let interface_name = args.interface;
    //TODO: add bad input handling

    /*---[Interface handling]---*/
    let interface = get_interface(interface_name);

    println!("{:#?}", interface);
}
