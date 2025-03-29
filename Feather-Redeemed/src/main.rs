use clap::{Parser};
use dns_lookup::lookup_addr;
use std::{time::Duration, fs::File, fs};
use std::net::{IpAddr, TcpStream, SocketAddr};
use std::collections::{HashMap,HashSet};
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

    #[arg(short = 'p', help = "Using this flag enables portscanning of all addresses in subnets (a /24 address block) with hosts in them.")]
    portscan: bool,
    
    #[arg(short = 'e', default_value="exclusions.txt", default_missing_value="exclusions.txt", help = "File of excluded hosts and subnets. (10.0.0.1 or 10.1.1.0/24) \nIf no -e flag specified. exclusions.txt will be used. \nWill auto exclude interfaces on the scanning computer.")]
    exclusions: String,

    #[arg(short = 'w', long = "ping", help = "Enable pingsweeps. WARNING: VERY SLOW RIGHT NOW.")]
    pingsweeps: bool,

    //#[arg(short = 'u', long = "udp", help = "Enable UDP scanning over TCP.")]
    //udp_enabled: bool,
}

type Db = Arc<Mutex<HashMap<String,String>>>;
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
    //PUT FANCY BANNER HERE LOL//
    let banner ="
 _   _         _  _     ______                                                                  
| | | |       | || |    | ___ \\                                                                 
| | | |  __ _ | || | __ | |_/ /  ___ __   __  ___  _ __    __ _   ___   __ _  _ __    ___   ___ 
| | | | / _` || || |/ / |    /  / _ \\\\ \\ / / / _ \\| '_ \\  / _` | / _ \\ / _` || '_ \\  / __| / _ \\
\\ \\_/ /| (_| || ||   <  | |\\ \\ |  __/ \\ V / |  __/| | | || (_| ||  __/| (_| || | | || (__ |  __/
 \\___/  \\__,_||_||_|\\_\\ \\_| \\_| \\___|  \\_/   \\___||_| |_| \\__, | \\___| \\__,_||_| |_| \\___| \\___|
                                                           __/ |                                
                                                          |___/                                 
";
    println!("{}",banner);
    println!("Use the flag -h for help with flags and commands.");


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
                //eprintln!("ASSUMPTION: CIDR is a /24 /16 or /8");
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
        //Dummy check if nothing was in the exclusions
        if ip_exclusions_list.len() == 0 && subnet_exclusions_list.len() == 0 {
            let mut input = String::new();
            
            println!("!!!-No Exclusions found in exclusions.txt before adding device intefaces.\nIf this is intentional type 'y' if not go check exclusions and type 'n'");
            print!("Would you like to continue: ");
            io::stdout().flush().unwrap(); //Have to flush to make the buffered write data actually output.

            io::stdin().read_line(&mut input).expect("Failed to read line");
            match input.trim() {
                "y" => println!("Continuing On"),
                "n" => panic!("Canceling. Go check exclusions and come back."),
                _ => panic!("INVALID::Your response is not a mundane detail Michael!"),
            }
        }
    }    
    //ADD this devices ip address to the excluded hosts list
    for iface in datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback(){
            let comp_ip = iface.ips[0].ip();
            ip_exclusions_list.insert(comp_ip.to_string());
        }
    }

    //DEBUG
    println!("\n<<====Excluding the Following Hosts and Subnets====>>");
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
    

    //Flag Check
    println!("<<======Flag Check======>>");
    //DEBUGGING Say whether pingsweeps are enabled   
    if cli.pingsweeps {
        eprintln!("[x] Pingsweeps Enabled");
    }
    else {
        eprintln!("[ ] Pingsweeps Disabled");
    }
    //DEBUGGING Say whether portscanning is enabled.
    if cli.portscan {
        eprintln!("[x] Portscanning Enabled");
    }
    else {
        eprintln!("[ ] Portscanning Disabled");
    }
    //=================RDNS and Pingsweeps================//
    //Perform rDNS searching for subnets with vaild hosts in them. 
    //Make a list of hostnames discovered and a list of subents (/24) with hosts in it.
    if cli.reverse_dns {
        eprintln!("[x] Reverse DNS Enabled");

        if cli.subnets =="A"{
            eprintln!("\n\n<<=======Reverse DNS Scanning=======>>");
            eprintln!("  Scanning Entire Private Subnet Space");
            eprintln!("  Output will be saved in ~/output/");
            rdns_and_ping_full_private(cli.portscan,cli.pingsweeps,subnet_exclusions_list,ip_exclusions_list).await;
        }               
        else {
            if cli.subnets.len()== 0{
                eprintln!("You done messesd up D-Nice! No subnet provided with the flag.");
            }
            else if cidr_pattern.is_match(cli.subnets.as_str()){
                eprintln!("rDNS lookup on proivided subnet only, {}",cli.subnets);
            }
            else {
                panic!("J-Quella, do you konw what a CIDR is? Or are your fingers to funky? You gave me this shenanigans {}", cli.subnets);           
            }
        }
    }
    else{
        eprintln!("Reverse DNS Disabled.");
    }
    //==========TIME TRACKING================//
    let elapsed = starttime.elapsed();
    eprintln!("The program took {} seconds to complete.", elapsed.as_secs());
}

//DESCRIPTION:
//TAKES:
//RETURNS:
async fn rdns_and_ping_full_private(en_portscan: bool, en_pingsweep: bool, mut sub_ex_list: HashSet<String>, mut ip_ex_list: HashSet<String>) {
    let mut subnets_with_hosts:Vec<String> = Vec::new();
    let list_of_hosts = Arc::new(Mutex::new(HashMap::new()));
    let copy_ip_ex_list: HashSet<String>  = ip_ex_list.clone(); 
    let rdns_time = std::time::Instant::now();
    //======================= rDNS Sweeping 10.0.0.0/8 ==========================================//
    for second_octet in 0..=MAX_OCTET {
        let ten_slash_8_time = std::time::Instant::now();
        eprintln!("    Scanning Subnet: 10.{}.0.0/16", second_octet);    
        for third_octet in 0..=MAX_OCTET {
            //Check if we need to skip SUBNET
            let subnet = format!("10.{}.{}.0",second_octet,third_octet);
            if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("    Skipping Subnet: {}", subnet);
                sub_ex_list.remove(&subnet);
                continue;
            }
               
            
            let mut tasks = JoinSet::new();
            let subnet_has_hosts = Arc::new(Mutex::new(false));
            
            for forth_octet in 1..MAX_OCTET {  //Non-inclusive since 255 will be broadcast
                //Check if we need to skip IP
                let ip = format!("10.{}.{}.{}", second_octet, third_octet, forth_octet);
                if ip_ex_list.len() > 0 && ip_ex_list.contains(&ip) {
                    eprintln!("    Skipping IP: {}", ip);
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
        let one72_slash_12_time = std::time::Instant::now();
        eprintln!("    Scanning Subnet: 172.{}.0.0/16", second_octet);
        for third_octet in 0..=MAX_OCTET {
            //Check if we need to skip SUBNET
            let subnet = format!("172.{}.{}.0",second_octet,third_octet); 
            if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("    Skipping Subnet: {}", subnet);
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
                    eprintln!("    Skipping IP: {}", ip);
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
        eprintln!("The Subnet 172.{}.0.0/16 took {} seconds to complete.", second_octet, one72_slash_12_time.elapsed().as_secs());     
    }


    //============================== rDNS Sweeping 192.168.0.0/16 ===========================// 
    //Only need the thrid and forth since the second does not change for this space.
    let one92_slash_16_time = std::time::Instant::now();
    for third_octet in 0..=MAX_OCTET {
        //Check if we need to skip SUBNET
        let subnet = format!("192.168.{}.0",third_octet); 
        if sub_ex_list.len() > 0 && sub_ex_list.contains(&subnet) {
                eprintln!("    Skipping Subnet: {}", subnet);
                sub_ex_list.remove(&subnet);
                continue;
        }
        //eprintln!("Scanning Subnet: 192.168.{}.0/24", third_octet); DEBUG        
        let mut tasks = JoinSet::new();
        let subnet_has_hosts = Arc::new(Mutex::new(false));

        for forth_octet in 1..MAX_OCTET {  //Non-inclusive since 255 will be broadcast
            //address.
            let ip = format!("192.168.{}.{}", third_octet, forth_octet);
            //Check if we need to skip IP
            if ip_ex_list.len() > 0 && ip_ex_list.contains(&ip) {
                eprintln!("    Skipping IP: {}", ip);
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
    eprintln!("The Subnet 192.162.0.0/16 took {} seconds to complete.", one92_slash_16_time.elapsed().as_secs());     
    eprintln!("Total RDNS time took {} seconds to complete.", rdns_time.elapsed().as_secs());     

    //========================PORT SCANNING===========================//
    //Use the List of Subnets with Hosts to Scan them for Open Ports 80,443,445
    if en_portscan {
        let list_of_hosts_clone = list_of_hosts.clone();
        let portscan_time = std::time::Instant::now();
        subnet_portscan(&subnets_with_hosts, list_of_hosts_clone, copy_ip_ex_list).await;
        eprintln!("Total Portscan time took {} seconds to complete.", portscan_time.elapsed().as_secs());     
        println!("<--Portscan Output saved in /output.-->");
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
    let subnet_results_file = match File::create(&subnet_results_file_path) {
        Err(e) => panic!("Couldn't Create {}: {}", display_sub, e),
        Ok(file) => file,
    };
    let mut sub_buff = BufWriter::new(subnet_results_file);
    for subnet in subnets_with_hosts.iter() {
        sub_buff.write_all(format!("{}\n",subnet).as_bytes()).expect("Unable to write subnets to subents.txt");
    }

    //Write Gathered Data to ip_hostname.txt and up_ips.txt
    let ip_host_results_file_path = Path::new("output/ip_hostname.txt");
    let up_ip_results_file_path = Path::new("output/up_ips.txt");
    let display_ip_host = ip_host_results_file_path.display();
    let display_up_ip = up_ip_results_file_path.display();
    
    //Create File and Create Write Buffer
    let ip_host_results_file = match File::create(&ip_host_results_file_path) {
        Err(e) => panic!("Couldn't Create {}: {}", display_ip_host, e),
        Ok(file) => file,
    };
    let mut ip_host_buff = BufWriter::new(ip_host_results_file);

    //Create File and Create Write Buffer
    let up_ip_results_file = match File::create(&up_ip_results_file_path) {
        Err(e) => panic!("Couldn't Create {}: {}", display_up_ip, e),
        Ok(file) => file,
    };
    let mut up_ip_buff = BufWriter::new(up_ip_results_file);
    
    //Loop through vector of host and ips "ip,hostname" and add them to output files.
    let list_of_hosts_clone = list_of_hosts.clone();
    for (ip, hostname) in list_of_hosts_clone.lock().unwrap().iter() {
        ip_host_buff.write_all(format!("{},{}\n",ip,hostname).as_bytes()).expect("Unable to write ip,hostname to ip_hostname.txt");
        up_ip_buff.write_all(format!("{}\n",ip).as_bytes()).expect("Unable to write ip to up_ips.txt");
    }
}

//DESCRIPTION:
//TAKES:
//RETURNS:
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
                list.insert(format!("{}",ip), "no_hostname".to_string());

            } //No Ping and No RDNS so NO host.
        } ,
        _ => {
            //Set the boolean to show there is a host on this subnet.
            let mut host_on_subnet_value = host_on_subnet.lock().unwrap(); 
            *host_on_subnet_value = true;
            //Access the Mutex Protected Host list and Add the IP and hostname to it.
            let mut list = host_list.lock().unwrap();
            list.insert(format!("{}",ip), format!("{}",hostname));
        }
    }
}

//DESCRIPTION:
//TAKES:
//RETURNS:
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
//DESCRIPTION:
//TAKES:
//RETURNS:
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

//DESCRIPTION:
//TAKES:
//RETURNS:
async fn subnet_portscan(subs_with_hosts: &Vec<String>, host_list: Db, mut ip_ex_hashmap: HashSet<String>) {
    //PORT SCANNING
    let all_ports = vec![80,443,445];
    
    let open_port_80_rfp = Path::new("output/80.txt");
    let open_port_443_rfp = Path::new("output/443.txt");
    let open_port_445_rfp = Path::new("output/445.txt");
    
    //OPEN Write Buffer for 80
    let open_port_80_rf = match File::create(&open_port_80_rfp) {
        Err(e) => panic!("Couldn't Create {}: {}", open_port_80_rfp.display(), e),
        Ok(file) => file,
    };
    let mut buff_80 = BufWriter::new(open_port_80_rf);

    //OPEN Write Buffer for 443
    let open_port_443_rf = match File::create(&open_port_443_rfp) {
        Err(e) => panic!("Couldn't Create {}: {}", open_port_443_rfp.display(), e),
        Ok(file) => file,
    };
    let mut buff_443 = BufWriter::new(open_port_443_rf);

    //OPEN Write Buffer for 445
    let open_port_445_rf = match File::create(&open_port_445_rfp) {
        Err(e) => panic!("Couldn't Create {}: {}", open_port_445_rfp.display(), e),
        Ok(file) => file,
    };
    let mut buff_445 = BufWriter::new(open_port_445_rf);


    
    //Make Sure Ouput Directory is there.
    match fs::create_dir_all("output") {
        Err(e) => panic!("Failed to Create Dir: {}", e),
        Ok(_) => {},
    }
    println!("//=============Begining Port Scans=========//");
    let max_tasks = MAX_OCTET as usize * all_ports.len();
    let mut tasks = Vec::with_capacity(max_tasks);
    for subnet in subs_with_hosts.iter() {
        for addr_octet in 0..=MAX_OCTET {
            let addr = subnet.replace("0/24",format!("{}",addr_octet).as_str());
            if ip_ex_hashmap.len() > 0 && ip_ex_hashmap.contains(&addr) {
                eprintln!("Skipping IP: {}", addr);
                ip_ex_hashmap.remove(&addr);
                continue;
            }
            for port in all_ports.iter() {   

                tasks.push(tokio::spawn(addr_portscan(addr.parse().unwrap(), *port)));
            }
        }        
    }
    for task in tasks {
        let result = task.await.unwrap();
        if result.0 {
            match result.2 {
                80 => buff_80.write_all(format!("{}\n",result.1).as_bytes()).expect("Unable to write data"),
                443 => buff_443.write_all(format!("{}\n",result.1).as_bytes()).expect("Unable to write data"),
                445 => buff_445.write_all(format!("{}\n",result.1).as_bytes()).expect("Unable to write data"),
                _ => println!("How in the BlAaAakE did we get here!"),
            }   
            ////======TODO ADD ANY NEW HOSTS TO THE HOSTS LIST===============//
            if !host_list.lock().unwrap().contains_key(&format!("{}",result.1)){
                //Access the Mutex Protected Host list and Add the IP and hostname to it.
                let mut list = host_list.lock().unwrap();
                list.insert(format!("{}",result.1), "no_hostname".to_string());
            }
        }
    }
}

//DESCRIPTION:
//TAKES:
//RETURNS: Tuple (true if port is open, ip, port);
async fn addr_portscan (host: IpAddr, port: u32) -> (bool, IpAddr, u32) {
    let socket: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    match TcpStream::connect_timeout(&socket, Duration::from_secs(1)) {
        Ok(_) => (true, host, port),
        Err(_) => (false, "0.0.0.0".parse().unwrap(), 0),
    }
}

