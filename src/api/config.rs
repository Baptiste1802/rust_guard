use config::{Config, File, FileFormat};

pub struct AppConfig {
    whitelisted_ports: Vec<u16>,
    whitelisted_ips: Vec<String>,
    honeypot_port: u16,
    whitelist_active: bool,
}

impl AppConfig {
    pub fn get_whitelisted_ports(&self) -> &Vec<u16> {
        &self.whitelisted_ports
    }

    pub fn get_whitelisted_ips(&self) -> &Vec<String> {
        &self.whitelisted_ips
    }

    pub fn get_honeypot_port(&self) -> u16 {
        self.honeypot_port
    }

    pub fn is_whitelist_active(&self) -> bool {
        self.whitelist_active
    }
}

pub fn load_config(config_path: &str) -> AppConfig {
    let builder = Config::builder()
        .add_source(File::new(config_path, FileFormat::Json));
    
    let settings = match builder.build() {
        Ok(cfg) => cfg,
        Err(err) => panic!("Failed loading config: {}", err),
    };

    let whitelisted_ports = load_whitelisted_ports(&settings);
    let whitelisted_ips = load_whitelisted_ips(&settings);
    let honeypot_port = load_honeypot_port(&settings);
    let whitelist_active = load_whitelist_active(&settings);

    AppConfig {
        whitelisted_ports,
        whitelisted_ips,
        honeypot_port,
        whitelist_active,
    }
}

fn load_whitelisted_ports(settings: &Config) -> Vec<u16> {
    match settings.get("whitelist.ports") {
        Ok(ports) => ports,
        Err(err) => panic!("Failed retrieving whitelisted ports: {}", err),
    }
}

fn load_whitelisted_ips(settings: &Config) -> Vec<String> {
    match settings.get("whitelist.ips") {
        Ok(ips) => ips,
        Err(err) => panic!("Failed retrieving whitelisted IPs: {}", err),
    }
}

fn load_honeypot_port(settings: &Config) -> u16 {
    match settings.get("honeypot_port") {
        Ok(port) => port,
        Err(err) => panic!("Failed retrieving honeypot port: {}", err),
    }
}

fn load_whitelist_active(settings: &Config) -> bool {
    match settings.get("whitelist_active") {
        Ok(active) => active,
        Err(err) => panic!("Failed retrieving whitelist active status: {}", err),
    }
}
