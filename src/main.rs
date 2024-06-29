use clap::Parser;
use rust_scanner::{run_syn_scan, Args, IpConfig};
use std::process;

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    let target_ports = args.ports;

    let ip_config = IpConfig::build(args.target, args.interface).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    let target_ip = ip_config.target_ip;

    println!("Ports : {:#?}\nIP : {:#?}\n\n", target_ports, target_ip);

    /*---[Scan]---*/
    let result = run_syn_scan(&ip_config, target_ports);
    println!("opened : {:#?}", result);
}
