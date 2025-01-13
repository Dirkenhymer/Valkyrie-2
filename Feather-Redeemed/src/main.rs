use clap::{Parser};

#[derive(Parser)]
#[command(version = "0.1")]
#[command(name = "Feather-Redeemed")]
#[command(about = "CLI tool to scan private subnets.", long_about = None)]
struct Cli {
    #[arg(short, action, help = "A flag that will enable reverse dns lookup.")] 
    reverse_dns: bool,
    
    #[arg(short, action, default_value="A", default_missing_value="A", help = "Specify Subnet in CRIDER notation or A for all private subnets.")]
    subnets: String,

    #[arg(short, long, num_args = 1.., value_delimiter = ',', default_value="445")]
    ports: Vec<i32>,
    
    #[arg(short, default_value="exclusions.txt", default_missing_value="exclusions.txt", help = "File of excluded hosts.")]
    exclusions: String,

    #[arg(short = 'w', long = "ping", help = "Enable pingsweeps on enumerated subents.")]
    pingsweeps: bool,

}

fn main() {
    let cli = Cli::parse();
  
    if cli.reverse_dns {
        println!("Reverse DNS Enabled");
    }
    else{
        println!("Reverse DNS Disabled");
    }
    
    if cli.subnets == "A"{
        println!("Scanning All Priate Addresses");
    }
    else {
        println!("Scanning {}", cli.subnets);
    }

    if cli.ports.len() >0 {
        println!("We will be scanning {:?} today.", cli.ports);
    }
    
    if cli.pingsweeps {
        println!("Pingsweeps Enabled");
    }
    else {
        println!("Pingsweeps Disabled");
    }

    println!("Using exclude file {}.", cli.exclusions);

    
}
