use clap::Parser;
use rust_scanner::{get_interface, run_syn_scan, Args};

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    let target_ports = args.ports.concat();

    let target_ips = args.targets;

    let interface = get_interface(args.interface);

    println!("Ports : {:#?}\nIP : {:#?}\n\n", target_ports, target_ips);

    /*---[Scan]---*/
    let _result = run_syn_scan(target_ips, target_ports, &interface);
    //println!("opened : {:#?}", result);
}
