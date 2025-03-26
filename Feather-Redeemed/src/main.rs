use clap::{Parser};
use dns_lookup::lookup_addr;
use std::{time::Duration, fs::File, fs};
use std::net::IpAddr;
use std::collections::HashSet;
use std::path::Path;
use std::io::{self, BufRead, BufWriter, Write};
use std::env::current_dir;
use regex::Regex;
use tokio::task::JoinSet;
use std::sync::{Arc, Mutex};
use pnet::datalink;


#[derive(Parser)]
#[command(version = "0.1")]
#[command(name = "Feather-Redeemed")]
#[command(about = "CLI tool to scan private internal subnets.", long_about = None)]

struct Cli {
    #[arg(short, action, help = "A flag that will enable reverse dns lookup.")] 
    reverse_dns: bool,
    
    #[arg(short = 's', action, default_value="A", default_missing_value="A", help = "Specify Subnet in CIDR notation or A for all private subnets.")]
    subnets: String,

    //#[arg(short = 'p', long, num_args = 1.., value_delimiter = ',', default_value="80,443,445")]
    //ports: Vec<i32>,
    
    #[arg(short = 'e', default_value="exclusions.txt", default_missing_value="exclusions.txt", help = "File of excluded hosts and subnets. (10.0.0.1 or 10.1.1.0/24) \nIf no -e flag specified. exclusions.txt will be used.")]
    exclusions: String,

    #[arg(short = 'w', long = "ping", help = "Enable pingsweeps. WARNING: VERY SLOW RIGHT NOW.")]
    pingsweeps: bool,

    //#[arg(short = 'u', long = "udp", help = "Enable UDP scanning over TCP.")]
    //udp_enabled: bool,
}

type Db = Arc<Mutex<Vec<String>>>;
type Sbool = Arc<Mutex<bool>>;

//GLOBAL VARIABLES
const MAX_OCTET: i32 =255 ; //Set this to 255 when ready for the full program.

#[tokio::main]
async fn main() {
    let starttime = std::time::Instant::now();
    let cli = Cli::parse();
    let cidr_pattern = Regex::new(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)($|/(8|16|24))?$").unwrap();
    let ip_pattern = Regex::new(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$").unwrap();
    let exclu_filename = cli.exclusions;
    let mut working_dir = current_dir().expect("Getting Current Directory Errored.");
    


    //==============Setting Up Exclusions========================//
    //Check for exclusions file. If it does not exists we exit! Need exclusions!
    println!("Using exclude file {}.", exclu_filename); //DEBUGGING
    
    let mut subnet_exclusions_list: HashSet<String> = HashSet::new();
    let mut ip_exclusions_list: HashSet<String> = HashSet::new();

    
    //Check and Make sure exclusions.txt or whatever specified file does exist.
    working_dir.push(&exclu_filename);
    let filepath = Path::new(working_dir.as_path());

    if !filepath.exists(){
        panic!("{} does not exist. Please create it before running this program. Path: {}", exclu_filename, filepath.display());
    }
   

    if let Ok(exclusions_lines) = read_lines(&exclu_filename){
        for line in exclusions_lines.map_while(Result::ok) {
            if ip_pattern.is_match(&line) { // IF line is an IP address
                ip_exclusions_list.insert(line);
            }
            else if cidr_pattern.is_match(&line) { // ELSE IF Line is a CIDR Address
                eprintln!("ASSUMPTION: CIDR is a /24 /16 or /8");
                let parts: Vec<&str> = line.split('/').collect(); //Split on "/" then collected into ["10.10.1.0", "24"]
                if parts[1] == "24" { //If a /24 CIDR
                    let ip_digits: Vec<&str> = parts[0].split('.').collect(); //Split the IP address
                    //into a vector ["10", "10", "1", "0"]
                    //Below is code for adding individual IP addresses out of a Subnet /24
                    /*for digit in 1..MAX_OCTET { //Uninclusive since 255 would be broadcast
                        exclusions_list.insert(format!("{}.{}.{}.{}",ip_digits[0],ip_digits[1],ip_digits[2],digit));
                    }*/
                    subnet_exclusions_list.insert(format!("{}.{}.{}.0",ip_digits[0],ip_digits[1],ip_digits[2]));
                }
                else {
                    //TODO:
                    eprintln!("TODO: That's something besides a /24 we need to implement that later");
                }
            }
            else {
                panic!("Something is wrong with the formatting of {}: Faulty Line >{}<", exclu_filename, line);
            }
        }
    }    
    //ADD this devices ip address to the excluded hosts list
    for iface in datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback(){
            let comp_ip = iface.ips[0].ip();
            println!("{}",comp_ip);
            ip_exclusions_list.insert(comp_ip.to_string());
        }
    }

    //DEBUG
    println!("\n====Excluding the Following Hosts and Subnets====");
    println!("Hosts:");
    for item in &ip_exclusions_list {
        eprintln!("{}",item);
    }
    println!("\nSubnets:");
    for item2 in &subnet_exclusions_list {
        eprintln!("{}/24", item2); //All skipped subnets will be a /24 as of right now. Maybe
        //consier a subnet list for each one: /24 /16 /8.
    }
    println!("\n\n");
    


    //==============Evaluate What Subnets to Scan================//
    //Figure out what subnets we will scan.
    if cli.subnets == "A"{
        eprintln!("Scanning All Private Addresses");
    }
    else { // CHECK if provided Subnet matches CIDR notation
        if cli.subnets.len()== 0{
            eprintln!("You done messesd up D-Nice! No subnet provided with the flag.");
        }
        else if cidr_pattern.is_match(cli.subnets.as_str()){
            eprintln!("Good boi Ti-mo-thee. We'll scan {} for ya.", cli.subnets);
        }
        else {
            panic!("J-Quella, do you konw what a CIDR is? Or are your fingers to funky? You gave me this shenanigans {}", cli.subnets);           
        }
    }
    

    //DEBUGGING Say whether Pingsweeps are Enabled   
    if cli.pingsweeps {
        eprintln!("Pingsweeps Enabled");
    }
    else {
        eprintln!("Pingsweeps Disabled");
    }
    //=================RDNS and Pingsweeps================//
    //Perform rDNS searching for subnets with vaild hosts in them. 
    //Make a list of hostnames discovered and a list of subents (/24) with hosts in it.
    if cli.reverse_dns {
        eprintln!("Reverse DNS Enabled");
        eprintln!("Starting Reverse DNS Scanning. Output will be saved in ~/rdns/rdns_results.txt");

        if cli.subnets =="A"{
            eprintln!("Scaning Entire Private Subnet Space 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16");
            rdns_and_ping_full_private(cli.pingsweeps,subnet_exclusions_list,ip_exclusions_list).await;
        }               
        else {
            eprintln!("rDNS lookup on proivided subnet only, {}",cli.subnets);
            //rdns_subnet();
        }

    }
    else{
        eprintln!("Reverse DNS Disabled.");
    }
    //==========TIME TRACKING================//
    let elapsed = starttime.elapsed();
    eprintln!("The program took {} seconds to complete.", elapsed.as_secs());
}

async fn rdns_and_ping_full_private(en_pingsweep: bool,mut sub_ex_list: HashSet<String>, mut ip_ex_list: HashSet<String>) {
    let mut subnets_with_hosts:Vec<String> = Vec::new();
    let list_of_hosts = Arc::new(Mutex::new(vec![]));

    //======================= rDNS Sweeping 10.0.0.0/8 ==========================================//
    for second_octet in 0..=MAX_OCTET {
        let ten_slash_8_time = std::time::Instant::now();
        eprintln!("Scanning Subnet: 10.{}.0.0/16", second_octet);    
        for third_octet in 0..=MAX_OCTET {
            //Check if we need to skip SUBNET
            let subnet = format!("10.{}.{}.0",second_octet,third_octet);
            if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("Skipping Subnet: {}", subnet);
                sub_ex_list.remove(&subnet);
                continue;
            }
               
            
            let mut tasks = JoinSet::new();
            let subnet_has_hosts = Arc::new(Mutex::new(false));
            
            for forth_octet in 1..MAX_OCTET {  //Non-inclusive since 255 will be broadcast
                //Check if we need to skip IP
                let ip = format!("10.{}.{}.{}", second_octet, third_octet, forth_octet);
                if ip_ex_list.len() > 0 && ip_ex_list.contains(&ip) {
                    eprintln!("Skipping IP: {}", ip);
                    ip_ex_list.remove(&ip);
                    continue;
                }

                let list_of_hosts_clone = list_of_hosts.clone();
                let subnet_has_hosts_clone = subnet_has_hosts.clone();
                let ip_addr_to_test = ip.parse().unwrap();
                tasks.spawn(async move{
                    //println!("Scanning IP Address -> 10.{}.{}.{}/24",second_octet, third_octet, forth_octet); //DEBUGGING
                    rdns_and_ping_ip(ip_addr_to_test, list_of_hosts_clone, subnet_has_hosts_clone, en_pingsweep).await;
                });
            }
            //Should wait for all spawned tasks to complete.
            tasks.join_all().await;

            let subnet_has_hosts_clone = subnet_has_hosts.clone(); 
            let mut subnet_value = subnet_has_hosts_clone.lock().unwrap(); 
            if *subnet_value {
                subnets_with_hosts.push(format!("10.{}.{}.0/24", second_octet, third_octet));
                *subnet_value = false;
            }
            //if (third_octet%4 == 0){
            //    thread::sleep(Duration::from_secs(1));
            //} 
        }
        eprintln!("The Subnet 10.{}.0.0/16 took {} seconds to complete.", second_octet, ten_slash_8_time.elapsed().as_secs());     
    }
    
    //========================= rDNS Sweeping 172.16.0.0/12 =========================//
    //Chaing the second_octect to match the CIDR Priavate Subnet Range Convention.
    for second_octet in 16..31 {
        eprintln!("Scanning Subnet: 172.{}.0.0/24", second_octet);
        for third_octet in 0..=MAX_OCTET {
            //Check if we need to skip SUBNET
            let subnet = format!("172.{}.{}.0",second_octet,third_octet); 
            if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("Skipping Subnet: {}", subnet);
                sub_ex_list.remove(&subnet);
                continue;
            } 
            
            let mut tasks = JoinSet::new();
            let subnet_has_hosts = Arc::new(Mutex::new(false));

            for forth_octet in 1..MAX_OCTET {  //Non-inclusive since 255 will be broadcast
                //address.
                let ip = format!("172.{}.{}.{}", second_octet, third_octet, forth_octet); 
                //Check if we need to skip IP
                if ip_ex_list.len() > 0 && ip_ex_list.contains(&ip) {
                    eprintln!("Skipping IP: {}", ip);
                    ip_ex_list.remove(&ip);
                    continue;
                }

                let list_of_hosts_clone = list_of_hosts.clone();
                let subnet_has_hosts_clone = subnet_has_hosts.clone();
                let ip_addr_to_test = ip.parse().unwrap();
                tasks.spawn(async move{
                    rdns_and_ping_ip(ip_addr_to_test, list_of_hosts_clone, subnet_has_hosts_clone, en_pingsweep).await;
                });
            }
            //Should wait for all spawned tasks to complete.
            tasks.join_all().await;

            let subnet_has_hosts_clone = subnet_has_hosts.clone(); 
            let mut subnet_value = subnet_has_hosts_clone.lock().unwrap(); 
            if *subnet_value {
                subnets_with_hosts.push(format!("172.{}.{}.0/24", second_octet, third_octet));
                *subnet_value = false;
            }
        }
    }
    //============================== rDNS Sweeping 192.168.0.0/16 ===========================// 
    //Only need the thrid and forth since the second does not change for this space.
    for third_octet in 0..=MAX_OCTET {
        //Check if we need to skip SUBNET
        let subnet = format!("192.168.{}.0",third_octet); 
        if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("Skipping Subnet: {}", subnet);
                sub_ex_list.remove(&subnet);
                continue;
        }
        eprintln!("Scanning Subnet: 192.168.{}.0/24", third_octet);
        
        let mut tasks = JoinSet::new();
        let subnet_has_hosts = Arc::new(Mutex::new(false));

        for forth_octet in 1..MAX_OCTET {  //Non-inclusive since 255 will be broadcast
            //address.
            let ip = format!("192.168.{}.{}", third_octet, forth_octet);
            //Check if we need to skip IP
            if ip_ex_list.len() > 0 && ip_ex_list.contains(&ip) {
                eprintln!("Skipping IP: {}", ip);
                ip_ex_list.remove(&ip);
                continue;
            }

            let list_of_hosts_clone = list_of_hosts.clone();
            let subnet_has_hosts_clone = subnet_has_hosts.clone();
            let ip_addr_to_test = ip.parse().unwrap();
            
            tasks.spawn(async move{
                rdns_and_ping_ip(ip_addr_to_test, list_of_hosts_clone, subnet_has_hosts_clone, en_pingsweep).await;
            });
        }
        //Should wait for all spawned tasks to complete.
        tasks.join_all().await;

        let subnet_has_hosts_clone = subnet_has_hosts.clone(); 
        let mut subnet_value = subnet_has_hosts_clone.lock().unwrap(); 
        if *subnet_value {
            subnets_with_hosts.push(format!("192.168.{}.0/24", third_octet));
            *subnet_value = false;
        }
    }    
    //========================Outputting Data=========================//
    //Write Data to Files
    //Create Output Folder
    match fs::create_dir_all("output") {
        Err(e) => panic!("Failed to Create Dir: {}", e),
        Ok(_) => {},
    }

    //Write Gathered Data to Subnets.txt
    let subnet_results_file_path = Path::new("output/subnets.txt");
    let display_sub = subnet_results_file_path.display();
    let mut subnet_results_file = match File::create(&subnet_results_file_path) {
        Err(e) => panic!("Couldn't Create {}: {}", display_sub, e),
        Ok(file) => file,
    };
    let mut sub_buff = BufWriter::new(subnet_results_file);
    for subnet in subnets_with_hosts.iter() {
        sub_buff.write_all(format!("{}\n",subnet).as_bytes()).expect("Unable to write data");
    }

    //Write Gathered Data to ip_hostname.txt
    let ip_host_results_file_path = Path::new("output/ip_hostname.txt");
    let display_ip_host = ip_host_results_file_path.display();
    let mut ip_host_results_file = match File::create(&ip_host_results_file_path) {
        Err(e) => panic!("Couldn't Create {}: {}", display_ip_host, e),
        Ok(file) => file,
    };
    let mut ip_host_buff = BufWriter::new(ip_host_results_file);

    let list_of_hosts_clone = list_of_hosts.clone();
    for host in list_of_hosts_clone.lock().unwrap().iter() {
        ip_host_buff.write_all(format!("{}\n",host).as_bytes()).expect("Unable to write data");
    }
}

async fn rdns_and_ping_ip(ip:IpAddr, host_list: Db, host_on_subnet: Sbool, pingsweeps_enabled: bool){
    let hostname = lookup_addr(&ip).unwrap_or("no_hostname".to_string());
    match hostname.as_str(){
        "no_hostname" => {
            //No Hostname so need to ping the IP address and see if that works.
            if pingsweeps_enabled && ping_host(ip, 200) {
                eprintln!("{} is reachable",ip);
                //Set the boolean to show there is a host on this subnet.
                let mut host_on_subnet_value = host_on_subnet.lock().unwrap(); 
                *host_on_subnet_value = true;
                //Access the Mutex Protected Host list and Add the IP and hostname to it.
                let mut list = host_list.lock().unwrap();
                list.push(format!("{},{}",ip, "no_hostname"));

            } //No Ping and No RDNS so NO host.
        } ,
        _ => {
            //Set the boolean to show there is a host on this subnet.
            let mut host_on_subnet_value = host_on_subnet.lock().unwrap(); 
            *host_on_subnet_value = true;
            //Access the Mutex Protected Host list and Add the IP and hostname to it.
            let mut list = host_list.lock().unwrap();
            list.push(format!("{},{}",ip, hostname));
        }
    }
}

fn ping_host(host: IpAddr, timeout_milis: u64) -> bool {
    let timeout = Duration::from_millis(timeout_milis);
    let data = [1,2,3,4]; //ping data
    let options = ping_rs::PingOptions {ttl: 128, dont_fragment: true};
    let result = ping_rs::send_ping(&host, timeout, &data, Some(&options));
    match result {
        Ok(_) => true,
        Err(_) => false,
    }
}
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
/*
fn portscan() {
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
    //PORT SCANNING
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

fn rdns_subnet () {

}

*/


