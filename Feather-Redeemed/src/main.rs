use clap::{Parser};
use dns_lookup::lookup_addr;
use std::{thread, time::Duration};
use std::net::{TcpStream, SocketAddr, IpAddr, Ipv4Addr};
use regex::Regex;

#[derive(Parser)]
#[command(version = "0.1")]
#[command(name = "Feather-Redeemed")]
#[command(about = "CLI tool to scan private subnets.", long_about = None)]

struct Cli {
    #[arg(short, action, help = "A flag that will enable reverse dns lookup.")] 
    reverse_dns: bool,
    
    //#[arg(short ='n', long = "nrdns", action,help = "If enabled the porgram will rely on nmap to do reverse DNS lookup. It assumes file.")]
    //nmap_reverse_dns: bool,

    #[arg(short, action, default_value="A", default_missing_value="A", help = "Specify Subnet in CRIDER notation or A for all private subnets.")]
    subnets: String,

    #[arg(short, long, num_args = 1.., value_delimiter = ',', default_value="80,443,445")]
    ports: Vec<i32>,
    
    #[arg(short, default_value="exclusions.txt", default_missing_value="exclusions.txt", help = "File of excluded hosts.")]
    exclusions: String,

    #[arg(short = 'w', long = "ping", help = "Enable pingsweeps on enumerated subents.")]
    pingsweeps: bool,

    //#[arg(short = 'u', long = "udp", help = "Enable UDP scanning over TCP.")]
    //udp_enabled: bool,
}

fn main() {
    let cli = Cli::parse();
    let cidr_pattern = Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$").unwrap();
    let max_octet = 255;
    let mut subnet_has_hosts = false;
    let mut subnets_with_hosts:Vec<String> = Vec::new();
    let mut subnets_to_pingsweep:Vec<String> = Vec::new();
    let mut list_of_hosts = Vec::new();
    //Check for exclusions file. If it does not exists we exit! Need exclusions!
    let mut exclusions:Vec<String> = Vec::new();
    println!("Using exclude file {}.", cli.exclusions);
    

    //Figure out what subnets we will scan.
    let mut subnets_to_rdns:Vec<&str> = Vec::new();
    if cli.subnets == "A"{
        println!("Scanning All Priate Addresses");
        subnets_to_rdns = vec!["10.0.0.8/8","172.16.0.0/12","192.168.0.0/16"];
    }
    else {
        println!("Scanning {}", cli.subnets);
        subnets_to_rdns = vec![cli.subnets.as_str()];
    }
    
    //Perform rDNS searching for subnets with vaild hosts in them. 
    //Make a list of hostnames discovered and a list of subents (/24) with hosts in it.
    if cli.reverse_dns {
        println!("Reverse DNS Enabled");
        println!("Starting Reverse DNS Scanning. Output will be saved in ~/rdns/rdns_results.txt");
        if (cli.subnets =="A"){
            println!("Scaning Entire Private Subnet Space 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16");

                        
            //rDNS Sweeping 10.0.0.0/8 First
            for second_octet in 0..=max_octet {
                for third_octet in 0..=max_octet {
                    for forth_octet in 1..max_octet {  //Non-inclusive since 255 will be broadcast
                        //address.
                        std::process::Command::new("clear").status().unwrap();
                        
                        println!("============Feather Redeemed=============");
                        println!("Scanning Subnet: 10.{}.{}.0/24", second_octet, third_octet);
                        println!("Scanning IP Address -> 10.{}.{}.{}/24",second_octet, third_octet, forth_octet);

                        let ip: std::net::IpAddr = format!("10.{}.{}.{}", second_octet, third_octet, forth_octet).parse().unwrap();
                        let hostname = lookup_addr(&ip).unwrap_or("no_hostname".to_string());
                        match hostname.as_str(){
                            "no_hostname" => println!("No hostname for {}",ip),
                            _ => {
                                //DEBUG PRINTLN -- REMOVE println!("Found host on {} with hostname {}",ip,hostname);
                                subnet_has_hosts = true;
                                list_of_hosts.push(format!("{} , {}",ip, hostname));
                            }
                        }

                        thread::sleep(Duration::from_millis(20));
                    }
                    if subnet_has_hosts {
                        subnets_with_hosts.push(format!("10.{}.{}.0/24", second_octet, third_octet));
                        subnet_has_hosts = false;
                    }
                }
            }
            //rDNS Sweeping 172.16.0.0/12
            //Chaing the second_octect to match the CIDR Priavate Subnet Range Convention.
            for second_octet in 16..31 {
                for third_octet in 0..=max_octet {
                    for forth_octet in 1..max_octet {  //Non-inclusive since 255 will be broadcast
                        //address.
                        std::process::Command::new("clear").status().unwrap();
                        
                        println!("============Feather Redeemed=============");
                        println!("Scanning Subnet: 172.{}.{}.0/24", second_octet, third_octet);
                        println!("Scanning IP Address -> 172.{}.{}.{}/24",second_octet, third_octet, forth_octet);

                        let ip: std::net::IpAddr = format!("172.{}.{}.{}", second_octet, third_octet, forth_octet).parse().unwrap();
                        let hostname = lookup_addr(&ip).unwrap_or("no_hostname".to_string());
                        match hostname.as_str(){
                            "no_hostname" => println!("No hostname for {}",ip),
                            _ => {
                                //DEBUG PRINTLN -- REMOVE println!("Found host on {} with hostname {}",ip,hostname);
                                subnet_has_hosts = true;
                                list_of_hosts.push(format!("{} , {}",ip, hostname));
                            }
                        }

                        thread::sleep(Duration::from_millis(20));
                    }
                    if subnet_has_hosts {
                        subnets_with_hosts.push(format!("172.{}.{}.0/24", second_octet, third_octet));
                        subnet_has_hosts = false;
                    }
                }
            }
            //rDNS Sweeping 192.168.0.0/16 
            //Only need the thrid and forth since the second does not change for this space.
            for third_octet in 0..=max_octet {
                for forth_octet in 1..max_octet {  //Non-inclusive since 255 will be broadcast
                    //address.
                    std::process::Command::new("clear").status().unwrap();
                    
                    println!("============Feather Redeemed=============");
                    println!("Scanning Subnet: 192.168.{}.0/24", third_octet);
                    println!("Scanning IP Address -> 192.168.{}.{}/24",third_octet, forth_octet);

                    let ip: std::net::IpAddr = format!("192.168.{}.{}", third_octet, forth_octet).parse().unwrap();
                    let hostname = lookup_addr(&ip).unwrap_or("no_hostname".to_string());
                    match hostname.as_str(){
                        "no_hostname" => println!("No hostname for {}",ip),
                        _ => {
                            //DEBUG PRINTLN -- REMOVE println!("Found host on {} with hostname {}",ip,hostname);
                            subnet_has_hosts = true;
                            list_of_hosts.push(format!("{} , {}",ip, hostname));
                        }
                    }

                    thread::sleep(Duration::from_millis(20));
                }
                if subnet_has_hosts {
                    subnets_with_hosts.push(format!("192.168.{}.0/24", third_octet));
                    subnet_has_hosts = false;
                }
            } 
        }
        else {
            println!("rDNS lookup on proivided subnet only, {}",cli.subnets);
        }
        println!("================================");
        println!("===Subnets with Hosts in them===");
        println!("================================");
        for subnet in subnets_with_hosts.iter() {
            println!("{}",subnet);
        }
        println!("================================");
        println!("======== List of Hosts =========");
        println!("================================");
        for host in list_of_hosts.iter() {
            println!("{}", host);
        }
    }
    else{
        println!("Reverse DNS Disabled. Portscanning Entire Provided Subnet");
        if (cli.subnets == "A"){
            println!("You done messed up A-A-Ron! We're not scanning the whole private subnet space.");
        }
        else if (cli.subnets.len()== 0){
            println!("You done messesd up D-Nice! No subnet provided with the flag.");
        }
        else if (cidr_pattern.is_match(cli.subnets)){
            println!("Good boi Ti-mo-thee. We'll scan that subnet for ya.");
        }
        else {
            println!("J-Quella, do you konw what a CIDR is? Or are your fingers to funky? You gave me this shenanigans {}", cli.subnets);
        }
    }

    if cli.pingsweeps {
        println!("Pingsweeps Enabled");
    }
    else {
        println!("Pingsweeps Disabled");
        if cli.ports.len() >0 {
            let all_ports = &cli.ports;
            let mut open_ports = Vec::new();

            println!("We will be scanning {:?} today.", cli.ports);
            println!("Starting with:");
            for subnet in subnets_with_hosts.iter() {
                for port in all_ports.iter() {

                    for addr_octet in 0..=254 {
                        let addr = subnet.replace("0/24",format!("{}",addr_octet).as_str());
                        println!("Port Scanning {} with port {}", addr, port);
                    
                        let socket: SocketAddr = format!("{}:{}", addr, port).parse().unwrap();
                        match TcpStream::connect_timeout(&socket, Duration::from_secs(1)) {
                            Ok(_) => {
                                open_ports.push(socket);
                            }
                            Err(_) => (),
                        }
                    }
                }
            }
        for open_hosts in open_ports.iter(){
            println!("{}",open_hosts);
        }
        }
    }
}

