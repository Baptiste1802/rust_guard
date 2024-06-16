use crate::api::packet_infos::PacketInfos;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;
use std::time::{Duration,Instant};
use pnet::ipnetwork::Ipv4Network;
use pnet::packet::arp::ArpOperations;
use pnet::util::MacAddr;

use super::layer_3::Layer3Infos;

#[derive(Debug)]
struct Entry {
    ip : Ipv4Addr,
    mac : MacAddr,
    timestamp : Instant 
}

impl PartialEq for Entry{
    fn eq(&self, other: &Self) -> bool{
        print!("Equals : {}\n",self.ip == other.ip || self.mac == other.mac);
        self.ip == other.ip && self.mac == other.mac
    }
}

impl Eq for Entry{}

impl Hash for Entry{
    fn hash<H: Hasher>(&self, state : &mut H){
        self.ip.hash(state);
        self.mac.hash(state);
    }
}

#[derive(Debug)]
pub struct ArpCache{
    cache: HashSet<Entry>,
    ttl: Duration,
    interface : Ipv4Network,
}

impl ArpCache{

    pub fn new(ttl: Duration, interface : Ipv4Network) -> Self {
        ArpCache{
            cache : HashSet::new(),
            ttl : ttl,
            interface : interface,
        }
    }

    pub fn insert(&mut self, ip : Ipv4Addr, mac: MacAddr) -> Result<(),String>{
        let timestamp = Instant::now();
        // let mut error = false;
        let new_entry : Entry = Entry {
            ip,
            mac,
            timestamp,
        };

        for entry in self.cache.iter(){
            println!("{:?}",entry);
        }

        println!("new_value : {:?}",new_entry);
        if self.cache.iter().any(|e| e.ip == new_entry.ip || e.mac == new_entry.mac){
            Err("Handle error : k1 != k2 -> hash(k1) != hash(k2)".to_string())
        }
        else{
            self.cache.insert(new_entry);
            Ok(())
        }
    }

    pub fn cleanup(&mut self){
        let now = Instant::now();
        self.cache.retain(|entry| now - entry.timestamp > self.ttl);
    }

    pub fn get(&mut self, entry :&Entry) -> Option<&Entry>{
        self.cleanup();
        self.cache.get(entry)
    }

    // pub fn process_packet(&mut self, ip : &Ipv4Addr, mac: &String) -> Option<&Ipv4Addr>{
    //     // Si l'adresse ip correspond à l'adresse de broadcast -> arp request 
    //     // Vérification de l'adresse IP conforme au sous réseau  -> arp request et reply
    //     // Vérification adresse mac source dans le paquet Ethernet conforme à celle dans le paquet arp -> arp request et reply
    //     // Ajout de le pair et vérification doublon -> Arp Reply
    //     // Endpoint une adresse mac valide (pas broadcast par exemple) -> Arp Reply
    // }
    fn network_verification(&mut self, packet : &PacketInfos) -> Result<(),String>{
        //get subnet of network interface
        match packet.get_layer_3_infos() {
            Layer3Infos::ARP(arp_handler) => {
                let ip_network = self.interface;
                if arp_handler.ip_source.is_broadcast() || arp_handler.ip_source.is_loopback(){
                    return Err("handle alert -> IP source not valid".to_string())
                }
                else if !(ip_network.contains(arp_handler.ip_source)){
                    return Err("handle alert -> Ip source not in subnet".to_string());
                }
                else if (arp_handler.operation == ArpOperations::Request) && (arp_handler.hw_source.is_broadcast()){
                    return Err("handle alert -> mac address not valid".to_string())
                }
                else if !(arp_handler.hw_source.eq(packet.get_sender_hw_addr())){
                    return Err("handle alert -> mac address Ip packet do not correspond to mac address ARP packet".to_string())
                }
                else{
                    return Ok(())
                }
            }
            _ => {return Err("Not an ARP packet".to_string())}
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
    fn test_arm_cache(){
        let interface : Ipv4Network = "192.168.1.1/24".parse().unwrap();

        let mut arp_cache = ArpCache::new(Duration::new(10, 0), interface);


        let result1 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 2), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        let result2 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 3), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        let result3 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 2), MacAddr::new(0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF));
        let result4 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 4), MacAddr::new(0x10, 0x10, 0x10, 0x10, 0x10, 0x10));
        let result5 = arp_cache.insert(Ipv4Addr::new(192, 168, 1, 5), MacAddr::new(0xFF, 0x10, 0x10, 0x14, 0x10, 0x10));
        
        assert_eq!(result1,Ok(()));
        assert_eq!(result2, Err("Handle error : k1 != k2 -> hash(k1) != hash(k2)".to_string()));
        assert_eq!(result3, Err("Handle error : k1 != k2 -> hash(k1) != hash(k2)".to_string()));
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
            assert_eq!(cache.network_verification(&fake_paquet_info),Err("handle alert -> IP source not valid".to_string()));
        }


        {
            let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let mut ethernet_packet : MutableEthernetPacket = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
            paquet_generator(
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC].into(),
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBF].into(),
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into(), 
                [192, 168, 1, 2].into(), 
                [192, 168, 1, 3].into(),
                &mut ethernet_packet,
                &mut arp_packet);
    
            ethernet_packet.set_payload(&arp_buffer);
    
    
            let fake_paquet_info : PacketInfos = PacketInfos::new(&interface_name, &ethernet_packet.to_immutable());
            assert_eq!(cache.network_verification(&fake_paquet_info),Err("handle alert -> mac address Ip packet do not correspond to mac address ARP packet".to_string()));
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
            assert_eq!(cache.network_verification(&fake_paquet_info),Err("handle alert -> Ip source not in subnet".to_string()));
        }
        



    }
}