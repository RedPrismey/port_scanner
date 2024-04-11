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

    #[arg(short, long, default_value="default_interface")]
    interface: String,
}

fn main() {
/*---[Argument parsing]---*/
    let args = Args::parse();

    let target = args.target;
    let ports = args.ports;
    let interface_name = args.interface;
//TODO: add bad input handling


/*---[Interface handling]---*/
    let all_interfaces = interfaces();

    if interface_name != "default_interface" {
        let interface: Option<&NetworkInterface> = all_interfaces
            .iter()
            .find(|e| e.name == interface_name);

        let interface: &NetworkInterface = match interface {
            Some(interface) => interface,
            None => panic!("Interface not found : {}", interface_name),
        };

        println!("Got network interface : {}", interface_name);

    } else {
        println!("No interface specified, trying to get the default one");

/*Try to find an interface that is up, isn't loopback and as an ip.
* If more than one interface could work, just takes the first one.*/
        let interface: Option<&NetworkInterface> = all_interfaces
            .iter()
            .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

        let interface: &NetworkInterface = match interface {
            Some(interface) => interface,
            None => panic!("Could not find any network interface that are up and have an IP"),
        };

        println!("Got network interface : {}", interface.name);
    }
}

