use clap::Parser;

/* ---[Argument Structure]---
*
* Handling arguments with clap (see : https://docs.rs/clap/latest/clap/)
* The arguments with no default value are considered required
* */
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    ip: String,

    #[arg(short, long)]
    ports: String,
}

fn main() {
    let args = Args::parse();

    println!("IP : {}", args.ip);
    println!("ports : {}", args.ports);
}
