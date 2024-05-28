use crate::api::packet_infos::PacketInfos;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Sub;
use std::time::{Duration,Instant};
use pnet::ipnetwork::{IpNetwork,Ipv4Network};
use pnet::packet::arp::{Arp, ArpOperations};
use pnet::datalink::NetworkInterface;
use pnet::packet::ipv4;

use super::layer_3::Layer3Infos;

pub struct ArpCache{
    cache: HashMap<Ipv4Addr,(String,Instant)>,
    ttl: Duration,
    interface : NetworkInterface,
}

impl ArpCache{

    pub fn new(ttl: Duration, interface : NetworkInterface) -> Self {
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

    pub fn process_packet(&mut self, ip : &Ipv4Addr, mac: &String) -> Option<&Ipv4Addr>{
        // Trop de demande arp provenant d'une IP -> arp request
        // Si l'adresse ip correspond à l'adresse de broadcast -> arp request 
        // Vérification de l'adresse IP conforme au sous réseau  -> arp request et reply
        // Vérification adresse mac source dans le paquet Ethernet conforme à celle dans le paquet arp -> arp request et reply
        // Ajout de le pair et vérification doublon -> Arp Reply
        // Endpoint une adresse mac valide (pas broadcast par exemple) -> Arp Reply
    }

    fn network_verification(&mut self, packet : &PacketInfos) -> Result<(),String>{
        //get subnet of network interface
        let ip_network = self.interface.ips[0];

        match packet.get_layer_3_infos() {
            Layer3Infos::ARP => {

            },
            _ => {println!("oui")}
        }

        match ip_network.is_ipv4(){
            true =>{
                match packet.operation{
                    ArpOperations::Reply => {
                        //ip valide
                        if packet.sender_proto_addr.is_broadcast() || packet.sender_proto_addr.is_loopback(){
                            return Err("Sender cannot be broadcast".to_string())
                        }//ip dans le sous réseau
                        else if Some(packet.sender_proto_addr).is_some() && ip_network.contains(IpAddr::from(packet.sender_proto_addr)){
                            return Ok(())
                        }
                        else if Some(packet.sender_hw_addr).is_some() && !(packet.sender_hw_addr.is_broadcast() || packet.sender_hw_addr.is_local()){
                            return Ok(())
                        }  
                        else {
                            return Err("Network configuration problem".to_string())
                        }
                    }
                    ArpOperations::Request => {
                        Ok(())
                    }
                }




            }   
            false =>{
                return Err("No IPV6 in ARP protocol".to_string())
            }
        }



    }





    //pub fn verification
}