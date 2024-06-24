use crate::api::errors;
use crate::api::packet_infos::PacketInfos;
use core::fmt;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration,Instant};
use pnet::ipnetwork::Ipv4Network;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::ArpOperations;
use pnet::util::MacAddr;
use pnet::datalink::NetworkInterface;
use super::errors::ArpCacheError;

use super::layer_3::{GetInformations, Layer3Infos};

#[derive(Debug)]
struct Entry {
    ip : Ipv4Addr,
    mac : MacAddr,
    timestamp : Instant 
}

impl PartialEq for Entry{
    fn eq(&self, other: &Self) -> bool{
        self.ip == other.ip && self.mac == other.mac
    }
}

impl Eq for Entry{}

impl Hash for Entry{
    fn hash<H: Hasher>(&self, state : &mut H){
        self.ip.hash(state);
    }
}


#[derive(Debug)]
pub struct ArpCache{
    cache: HashSet<Entry>,
    ttl: Duration,
    interface : Ipv4Network,
    interface_name : String,
}

impl ArpCache{

    pub fn new(ttl: Duration, interface : &NetworkInterface) -> Self {
        let inter = match interface.ips.get(0){
            Some(IpNetwork::V4(ipv4)) => Some(*ipv4),
            _ => None,
        };

        ArpCache{
            cache : HashSet::new(),
            ttl,
            interface: inter.unwrap(),
            interface_name : interface.name.clone(),
        }
    }

    pub fn insert(&mut self, ip : Ipv4Addr, mac: MacAddr) -> Result<(),ArpCacheError>{
        let timestamp = Instant::now();
        // let mut error = false;
        let new_entry : Entry = Entry {
            ip,
            mac,
            timestamp,
        };

        if self.cache.iter().any(|e| e.ip == new_entry.ip || e.mac == new_entry.mac){
            println!("SpoofingAlert : Duplicated IP or MAC address detected, {}/{}",new_entry.ip, new_entry.mac);
            let err = ArpCacheError::SpoofingAlert{
                ip : new_entry.ip.to_string(),
                mac: new_entry.mac.to_string(),
            };
            errors::log_error(&err);
            Err(err)
        }
        else{
            self.cache.insert(new_entry);
            Ok(())
        }
    }

    pub fn to_string(&mut self){
        for entry in self.cache.iter(){
            println!(
                "({}) at ({}) on {}", entry.ip.to_string(),entry.mac.to_string(), self.interface_name
            );
        }
    }

    pub fn cleanup(&mut self){
        let now = Instant::now();
        self.cache.retain(|entry| (now.duration_since(entry.timestamp) < self.ttl));
    }

    fn get_by_ip(&mut self, ip :Ipv4Addr) -> Option<&Entry>{
        self.cleanup();
        for entry in self.cache.iter(){
            if entry.ip.eq(&ip){
                return Some(entry)
            }
        }
        None
    }

    // pub fn process_packet(&mut self, ip : &Ipv4Addr, mac: &String) -> Option<&Ipv4Addr>{
    //     // Si l'adresse ip correspond à l'adresse de broadcast -> arp request 
    //     // Vérification de l'adresse IP conforme au sous réseau  -> arp request et reply
    //     // Vérification adresse mac source dans le paquet Ethernet conforme à celle dans le paquet arp -> arp request et reply
    //     // Ajout de le pair et vérification doublon -> Arp Reply
    //     // Endpoint une adresse mac valide (pas broadcast par exemple) -> Arp Reply
    // }
    pub fn network_verification(&mut self, packet : &PacketInfos) -> Result<(),ArpCacheError>{
        match packet.get_layer_3_handler(){
            Layer3Infos::ARP(arp_handler) => {
                let ip_network = self.interface;

                if let IpAddr::V4(ip_source) = arp_handler.get_ip_src() {

                    if ip_source.is_broadcast() || arp_handler.ip_source.is_loopback(){
                        println!("NetworkError : invalid ip");
                        let err = ArpCacheError::InvalidIpSource { ip_source: arp_handler.ip_source.to_string() };
                        errors::log_error(&err);
                        return Err(err)
                    }
                    else if !(ip_network.contains(*ip_source)){
                        println!("NetworkError : handler not in subnet");
                        let err = ArpCacheError::SubnetError { ip: arp_handler.ip_source.to_string() };
                        errors::log_error(&err);
                        return Err(err)
                    }
                    else if (arp_handler.operation == ArpOperations::Request) && (arp_handler.hw_source.is_broadcast()){
                        println!("NetworkError : Mac address source cannot be broadcast address");
                        let err = ArpCacheError::HwBroadError { mac: arp_handler.hw_source.to_string()};
                        errors::log_error(&err);
                        return Err(err)
                    }
                    else if !(arp_handler.hw_source.eq(packet.get_mac_source())){
                        println!("NetworkError : Mac in Ethernet packet not equal to Mac in ARP packet");
                        let err = ArpCacheError::HwEtherArpError { macEther: packet.get_mac_source().to_string(), macARP: arp_handler.hw_source.to_string() };
                        errors::log_error(&err);
                        return Err(err)
                    } else{
                        match arp_handler.get_ip_src(){
                            IpAddr::V4(ipv4) => {
                                let result = self.insert(*ipv4, arp_handler.hw_source);
                                return result
                            }
                            IpAddr::V6(_) =>{
                                println!("NetworkError: IP source is not IPv4");
                                let err: ArpCacheError = ArpCacheError::InvalidIpSource {
                                    ip_source: arp_handler.ip_source.to_string(),
                                };
                            }
                        }
                        return Ok(())
                    }

                } else {
                    println!("NetworkError: IP source is not IPv4");
                    let err = ArpCacheError::InvalidIpSource {
                        ip_source: arp_handler.ip_source.to_string(),
                    };
                    errors::log_error(&err);
                    return Err(err);
                }
            }
            _ => {
                let err = ArpCacheError::NetworkError;
                return Err(err)
            }
        }
    }



    //pub fn verification
}


#[cfg(test)]
mod tests{
    use super::*;
    use std::time::Duration;
    use pnet::{packet::{arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}}, util::MacAddr};
    use crate::api::packet_infos::PacketInfos;

    fn paquet_generator<'a>(ether_mac_source : MacAddr,arp_mac_source : MacAddr,  mac_dest : MacAddr , ip_source : Ipv4Addr, ip_dest : Ipv4Addr,  ethernet_packet : &mut MutableEthernetPacket,  arp_packet : &mut MutableArpPacket){

        ethernet_packet.set_destination(mac_dest);
        ethernet_packet.set_source(ether_mac_source);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4); // IPv4
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(arp_mac_source);
        arp_packet.set_sender_proto_addr(ip_source);
        arp_packet.set_target_hw_addr([0; 6].into()); // Target MAC
        arp_packet.set_target_proto_addr(ip_dest); // Target IP

    }

    #[test]
    fn test_get_by_ip(){
        let all_interfaces = interfaces();

        // search for the default interface
        // up, not lootback and has an IP
        let default_interface = all_interfaces
            .iter()
            .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
    
        let default_interface = match default_interface {
            Some(interface) => interface,
            None => {
                println!("Error while finding the default interface.");
                std::process::exit(1);
            }
        };
        let mut arp_cache = ArpCache::new(Duration::new(2, 0), default_interface);
        let ip_to_test = Ipv4Addr::new(192, 168, 1, 10);
        let mac_to_test  =  MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x80, 0x80);
        arp_cache.insert(ip_to_test, mac_to_test).unwrap();
        let entry  = arp_cache.get_by_ip(ip_to_test);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.ip, ip_to_test);
        assert_eq!(entry.mac,mac_to_test);

    }

    #[test]
    fn test_arm_cache(){
        let interface : Ipv4Network = "192.168.1.1/24".parse().unwrap();

        let mut arp_cache = ArpCache::new(Duration::new(10, 0), interface);

        let result1 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 2), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        let result2 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 3), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        let result3 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 2), MacAddr::new(0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF));
        let result4 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 4), MacAddr::new(0x10, 0x10, 0x10, 0x10, 0x10, 0x10));
        let result5 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 5), MacAddr::new(0xFF, 0x10, 0x10, 0x14, 0x10, 0x10));

        arp_cache.to_string();

        assert_eq!(result1,Ok(()));
        // assert_eq!(result2, Err(ArpCacheError::SpoofingAlert));
        // assert_eq!(result3, Err(ArpCacheError::SpoofingAlert));
        assert_eq!(result4, Ok(()));
        assert_eq!(result5, Ok(()));
    }

    #[test]
    fn test_network_verification(){
        
        
        //cache arp
        let interface : Ipv4Network = "192.168.1.1/24".parse().unwrap(); 
        let mut cache = ArpCache::new(Duration::new(50, 0), interface);
        let interface_name = String::from("eth1");
        
        // Définissez les adresses MAC source et de destination
        let mut ethernet_buffer  = [0u8; 42];
        let mut arp_buffer = [0u8;28];

        {
            let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let mut ethernet_packet : MutableEthernetPacket = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
            paquet_generator(
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(),
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(), 
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into(), 
                [192, 168, 1, 2].into(), 
                [192, 168, 1, 3].into(),
                &mut ethernet_packet,
                &mut arp_packet);
    
            ethernet_packet.set_payload(&arp_buffer);
    
    
            let fake_paquet_info : PacketInfos = PacketInfos::new(&interface_name, &ethernet_packet.to_immutable());
            assert_eq!(cache.network_verification(&fake_paquet_info),Ok(()));

            cache.to_string();
        }

        {
            let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let mut ethernet_packet : MutableEthernetPacket = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
            paquet_generator(
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(),
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(), 
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into(), 
                [255,255,255,255].into(), 
                [192, 168, 1, 3].into(),
                &mut ethernet_packet,
                &mut arp_packet);
    
            ethernet_packet.set_payload(&arp_buffer);
    
    
            let fake_paquet_info : PacketInfos = PacketInfos::new(&interface_name, &ethernet_packet.to_immutable());
            assert_eq!(cache.network_verification(&fake_paquet_info),Err(ArpCacheError::InvalidIpSource { ip_source: fake_paquet_info.get_ip_src().unwrap().to_string()}));
        }


        {
            let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let mut ethernet_packet : MutableEthernetPacket = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
            paquet_generator(
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(),
                [0x12, 0x34, 0x56, 0x78, 0x98, 0x41].into(),
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into(), 
                [192, 168, 1, 2].into(), 
                [192, 168, 1, 3].into(),
                &mut ethernet_packet,
                &mut arp_packet);
    
            ethernet_packet.set_payload(&arp_buffer);
    
    
            let fake_paquet_info : PacketInfos = PacketInfos::new(&interface_name, &ethernet_packet.to_immutable());
            // assert_eq!(cache.network_verification(&fake_paquet_info),Err(ArpCacheError::HwEtherArpError { macEther: fake_paquet_info.get_mac_source().to_string(), macARP: MacAddr::new(12, 34, 56, 78, 98, 41).to_string() }));
        }

        {
            let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let mut ethernet_packet : MutableEthernetPacket = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
            paquet_generator(
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(),
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(), 
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into(), 
                [178, 16, 1, 2].into(), 
                [192, 168, 1, 3].into(),
                &mut ethernet_packet,
                &mut arp_packet);
    
            ethernet_packet.set_payload(&arp_buffer);
    
    
            let fake_paquet_info : PacketInfos = PacketInfos::new(&interface_name, &ethernet_packet.to_immutable());
            assert_eq!(cache.network_verification(&fake_paquet_info),Err(ArpCacheError::SubnetError { ip: fake_paquet_info.get_ip_src().unwrap().to_string() }));
        }
    }
}