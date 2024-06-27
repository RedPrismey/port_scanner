use clap::Parser;
use rust_scanner::{syn_scan, Args, Config};

fn main() {
    /*---[Argument parsing]---*/
    let args = Args::parse();

    let config = Config::build(args);

    let ip = config.target_ip;
    let port = config.target_port;

    println!("Port : {}\nIP : {:#?}\n\n", port, ip);

    /*---[Scan]---*/
    let result = syn_scan(&config);
    println!("opened : {}", result);
}
