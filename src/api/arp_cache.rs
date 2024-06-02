use crate::api::packet_infos::PacketInfos;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Sub;
use std::time::{Duration,Instant};
use pnet::ipnetwork::Ipv4Network;
use pnet::packet::arp::{Arp, ArpOperations};
use pnet::datalink::NetworkInterface;
use pnet::packet::ipv4;

use super::layer_3::Layer3Infos;
use super::packet_infos;

pub struct ArpCache{
    cache: HashMap<Ipv4Addr,(String,Instant)>,
    ttl: Duration,
    interface : Ipv4Network,
}

impl ArpCache{

    pub fn new(ttl: Duration, interface : Ipv4Network) -> Self {
        ArpCache{
            cache : HashMap::new(),
            ttl : ttl,
            interface : interface,
        }
    }

    pub fn insert(&mut self, ip : Ipv4Addr, mac: String){
        match self.cache.contains_key(&ip){
            true => {println!("Pair IP/MAC valide")},
            false => {println!("Pair IP/MAC invalide")},
        };
        let timestamp = Instant::now() + self.ttl;
        self.cache.insert(ip,(mac, timestamp));
    }

    pub fn cleanup(&mut self){
        let now = Instant::now();
        self.cache.retain(|_, &mut (_,timestamp)| timestamp > now);
    }

    pub fn get(&mut self, ip :&Ipv4Addr) -> Option<&String>{
        self.cleanup();
        self.cache.get(ip).map(|&(ref mac,_)|mac)
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
                match arp_handler.operation {
                    ArpOperations::Reply => {
                        if arp_handler.ip_source.is_broadcast() || arp_handler.ip_source.is_loopback(){
                            return Err("IP source cannot be broadcast address".to_string())
                        }
                        else if !(ip_network.contains(arp_handler.ip_source)){
                            return Err("Ip source not in subnet".to_string());
                        }
                        else if arp_handler.hw_source.is_broadcast() || arp_handler.hw_source.is_local(){
                            return Err("handle alert".to_string())
                        }
                        else{
                            return Ok(())
                        }
                    }   
                    ArpOperations::Request => {
                        if arp_handler.ip_source.is_broadcast() || arp_handler.ip_source.is_loopback(){
                            return Err("IP source cannot be broadcast address".to_string())
                        }
                        else if !(ip_network.contains(arp_handler.ip_source)){
                            return Err("Ip source not in subnet".to_string());
                        }
                        else if !(arp_handler.hw_source.eq(packet.get_sender_hw_addr())){
                            return Err("handle alert -> mac address Ip packet do not correspond to mac address ARP packet".to_string())
                        }
                        else{
                            return Ok(())
                        }
                    }
                    _ => {return Err("ARP error".to_string())}
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
            assert_eq!(cache.network_verification(&fake_paquet_info),Err("IP source cannot be broadcast address".to_string()));
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
            assert_eq!(cache.network_verification(&fake_paquet_info),Err("Ip source not in subnet".to_string()));
        }
        



    }
}