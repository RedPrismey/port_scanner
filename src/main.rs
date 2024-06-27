use clap::Parser;
use rust_scanner::{syn_scan, Args, Config};
use std::process;

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    let config = Config::build(args).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    let ip = config.target_ip;
    let port = config.target_port;

    println!("Port : {}\nIP : {:#?}\n\n", port, ip);

    /*---[Scan]---*/
    let result = syn_scan(&config);
    println!("opened : {}", result);
}
