use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    ip: String,
}

fn main() {
    let args = Args::parse();

    println!("Hello {}!", args.ip);
}
