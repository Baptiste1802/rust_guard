use std::collections::HashMap;
use std::hash::Hash;
use std::iter::Map;
use std::time::{SystemTime, Duration};
use pnet::packet::arp::ArpOperation;
use uuid::{uuid, Uuid};
use chrono::offset::Utc;
use chrono::{DateTime, Local, TimeZone};
use std::thread::{self, JoinHandle};
use std::sync::{Arc, Condvar, Mutex};
use std::fmt;
use crate::api::packet_map;

use super::layer_3::{self, EncapsulatedProtocolInfos, Layer3Infos};
use super::packet_infos::{self, PacketInfos};

pub struct PacketMapInfo {
    pub ready: bool,
    pub number_of_packets: usize,
    pub protocols: HashMap<String, u64>,
    pub mac_srcs: HashMap<String, u64>,
    pub mac_dsts: HashMap<String, u64>,
    pub ip_srcs: HashMap<String, u64>,
    pub ip_dsts: HashMap<String, u64>,
    pub port_srcs: HashMap<String, u64>,
    pub port_dsts: HashMap<String, u64>,
    pub tcp_flags: HashMap<Vec<String>, u64>,
    pub ip_src_port_dsts: HashMap<String, Vec<String>>, // Port scanning
    pub ip_dst_ip_srcs: HashMap<String, Vec<String>>, // DDOS
    pub ip_dst_and_protocol: HashMap<(String, String), u64>, // DOS
    pub arps: HashMap<(String, String), u64> // ipsrc, operation : ipdst, macsrc, macdst
    // stocker dans une struct ip _src ip_dst pour savoir quelle ip bannir
}

impl PacketMapInfo {
    pub fn new() -> Self {
        PacketMapInfo {
            ready: false,
            number_of_packets: 0,
            protocols: HashMap::new(),
            mac_srcs: HashMap::new(),
            mac_dsts: HashMap::new(),
            ip_srcs: HashMap::new(),
            ip_dsts: HashMap::new(),
            port_srcs: HashMap::new(),
            port_dsts: HashMap::new(),
            tcp_flags: HashMap::new(),
            ip_src_port_dsts: HashMap::new(),
            ip_dst_ip_srcs: HashMap::new(),
            ip_dst_and_protocol: HashMap::new(),
            arps: HashMap::new(),
        }
    }
    pub fn clear(&mut self) {
        self.protocols.clear();
        self.mac_srcs.clear();
        self.mac_dsts.clear();
        self.ip_srcs.clear();
        self.ip_dsts.clear();
        self.port_srcs.clear();
        self.port_dsts.clear();
        self.tcp_flags.clear();
        self.ip_src_port_dsts.clear();
        self.ip_dst_ip_srcs.clear();
        self.ip_dst_and_protocol.clear();
        self.arps.clear();
    }

    pub fn analyze(&mut self) {
        // if self.number_of_packets > 5000 {
        //     println!("DOS ATTACK RECOGNIZED : {}", self.number_of_packets);
        // }

        println!("{:?}", self.arps);

        self.arps.iter().filter(| &((ip_src, operation), counter) | {
            *counter > 100
        })
        .for_each(| ((ip_src, operation), counter) | {
            println!("ARP FLOODING FROM {} USING {} [{} packets]", ip_src, operation, counter);
        });

        self.ip_srcs.iter().filter(|&(_ip_src, counter)| {
            *counter > 1000
        })
        .for_each(|(ip_src, counter)| {
            println!("HOST {} SENDING A LARGE AMOUNT OF PACKETS [{} packets]", ip_src, counter);
        });

        self.ip_src_port_dsts.iter().filter(|&(_ip_src, port_dsts)| {
            port_dsts.len() > 10
        })
        .for_each(|(ip_src, port_dsts)| {
            println!("PORT SCAN RECOGNIZED FROM {} [{} ports scanned]\n{:?}", ip_src, port_dsts.len(), port_dsts);
        });

        self.ip_dst_ip_srcs.iter().filter(|&(_ip_dst, ip_srcs)| {
            ip_srcs.len() > 10
        })
        .for_each(|(ip_dst, ip_srcs)| {
            println!("DDOS ATTACK RECOGNIZED ON {} [{} packets]", ip_dst, ip_srcs.len());
            // println!("DDOS ATTACK RECOGNIZED ON {}\nIP srcs {:?}", ip_dst, ip_srcs);
        });

        self.ip_dst_and_protocol.iter().filter(| &((_ip_dst, _protocol), counter) | {
            *counter > 5000
        })
        .for_each(|((ip_dst, protocol), counter)| {
            match protocol.as_str() {
                "ICMP" => println!("ICMP FLOODING RECOGNIZED ON {} [{} packets]", ip_dst, counter),
                "UDP" => println!("UDP DOS ATTACK RECOGNIZED ON {} [{} packets]", ip_dst, counter),
                "TCP" => {
                    self.tcp_flags
                        .iter()
                        .filter(|&(_vec, number)| *number > counter/4 )
                        .for_each(|(flags, number)| {
                            println!("TCP {} DOS ATTACK RECOGNIZED ON {} [{} packets]", flags.join(", "), ip_dst, number);
                        });

                    // if no match
                    if self.tcp_flags.iter().all(|(_, &number)| number <= counter / 4) {
                        println!("TCP DOS ATTACKS RECOGNIZED ON {}, UNKOWN METHOD [{} packets]", ip_dst, counter);
                    }
                }
                _ => println!("DOS ATTACK RECOGNIZED ON {} USING {} [{} packets]", ip_dst, protocol, counter),            
            }
        });

        self.ready = false;
    }

    pub fn set_ready(&mut self) {
        self.ready = true;
    }

}

impl fmt::Display for PacketMapInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        writeln!(f, "Packet Infos:\nNumber of packets: {}", self.number_of_packets)?;
        writeln!(f, "----------\nProtocols:")?;
        for (protocol, number) in self.protocols.iter() {
            writeln!(f, "Protocol: {} : {} packets", protocol, number)?;
        }
        writeln!(f, "----------\nMac srcs:")?;
        for (mac_src, number) in self.mac_srcs.iter() {
            writeln!(f, "MAC src: {} : {} packets", mac_src, number)?;
        }  
        writeln!(f, "----------\nMac dsts:")?;
        for (mac_dst, number) in self.mac_dsts.iter() {
            writeln!(f, "MAC dst: {} : {} packets", mac_dst, number)?;
        }
        writeln!(f, "----------\nIP srcs:")?;
        for (ip_src, number) in self.ip_srcs.iter() {
            writeln!(f, "IP src: {} : {} packets", ip_src, number)?;
        }  
        writeln!(f, "----------\nIP dsts:")?;
        for (ip_dst, number) in self.ip_dsts.iter() {
            writeln!(f, "IP dst: {} : {} packets", ip_dst, number)?;
        } 
        writeln!(f, "----------\nPort srcs:")?;
        for (port_src, number) in self.port_srcs.iter() {
            writeln!(f, "Port src: {} : {} packets", port_src, number)?;
        }     
        writeln!(f, "----------\nPort dsts:")?;
        for (port_dst, number) in self.port_dsts.iter() {
            writeln!(f, "Port dst: {} : {} packets", port_dst, number)?;
        }
        writeln!(f, "----------\nTCP flags:")?;
        for (flags, number) in self.tcp_flags.iter() {
            writeln!(f, "Flags {:?} : {} packets", flags, number)?;
        }

        Ok(())
    }
}
pub struct PacketMap {
    packets:  HashMap<Uuid, PacketInfos>,
}

impl PacketMap {
    pub fn new() -> Self {
        PacketMap {
            packets: HashMap::new(),
        }
    }

    pub fn add_packet(&mut self, packet: PacketInfos) {
        let id = Uuid::new_v4();
        self.packets.insert(id, packet.clone());
    }

    pub fn remove_packet(&mut self, uuid: Uuid) {
        self.packets.remove(&uuid);
    }

    pub fn cleanup_old_packets(&mut self, secs: u64) {
        let now = SystemTime::now();
        let datetime: DateTime<Utc> = now.into();
        let datetime = datetime.with_timezone(&Local);
        println!("Now: {}",  datetime.format("%d/%m/%Y %T") );
        let duration = now - Duration::from_secs(secs);
        let datetime: DateTime<Utc> = duration.into();
        let datetime = datetime.with_timezone(&Local);
        println!("duration: {}", datetime.format("%d/%m/%Y %T"));


        let old_packets: Vec<Uuid> = self.packets.iter()
            .filter(|(_, packet)| packet.received_time() < &duration)
            .map(|(id, _)| *id)
            .collect();

        for id in old_packets {
            self.packets.remove(&id);
        }
    }

    pub fn get_statistics(&self, packet_map_infos: Arc<(Mutex<PacketMapInfo>, Condvar)>) {

        // implémenter les détections layer 2

        let (mutex, _) = &*packet_map_infos;
        let mut packet_map_infos = mutex.lock().unwrap();
        packet_map_infos.number_of_packets = self.packets.len();

        for (_, packet) in self.packets.iter() {

            // mac
            *packet_map_infos.mac_srcs.entry(packet.get_mac_source().to_string()).or_insert(0) += 1;
            *packet_map_infos.mac_dsts.entry(packet.get_mac_destination().to_string()).or_insert(0) += 1;

            // layer 3 
            let protocol_3 = packet.get_string_protocol_3();
            if protocol_3.to_string() == "Arp" {
                // made in a hurry
                if let Some((ip_src, ip_dst, hw_src, hw_dst, operation)) = packet.get_layer_3_handler().get_arp_infos() {
                    *packet_map_infos.arps.entry((ip_src.clone(), operation.to_string()))
                        .or_insert(0) += 1;
                }
            }
            *packet_map_infos.protocols.entry(protocol_3.clone()).or_insert(0) += 1;
            
            let ip_src = if let Some(ip_src) = packet.get_ip_src() {
                *packet_map_infos.ip_srcs.entry(ip_src.clone()).or_insert(0) += 1;
                Some(ip_src)
            } else {
                None
            };

            let ip_dst = if let Some(ip_dst) = packet.get_ip_dst() {
                *packet_map_infos.ip_dsts.entry(ip_dst.clone()).or_insert(0) += 1;
                
                // ip_dst : Vec<ip_src>
                if let Some(ip_src) = ip_src {
                    let vec = packet_map_infos.ip_dst_ip_srcs
                        .entry(ip_dst.clone())
                        .or_insert_with(Vec::new);

                    if !vec.contains(ip_src) {
                        vec.push(ip_src.clone());
                    }
                }

                Some(ip_dst)
            } else {
                None
            };

            if let Some(encapsulated_protocol) = packet.get_layer_3_handler().get_encapsulated_infos() {
                
                let protocol = match encapsulated_protocol {
                    EncapsulatedProtocolInfos::ICMP(_icmp_packet) => {
                        // TODO : handling ICMP type 
                        *packet_map_infos.protocols.entry("ICMP".to_string()).or_insert(0) += 1;
                        "ICMP".to_string()
                    }
                };

                // (ip_dst, protocol) : counter
                if let Some(ip_dst) = ip_dst {
                    *packet_map_infos.ip_dst_and_protocol.entry((ip_dst.clone(), protocol)).or_insert(0) += 1;
                }

            }

            // layer 4
            else if let Some(protocol_4) = packet.get_string_protocol_4() {
                *packet_map_infos.protocols.entry(protocol_4.clone()).or_insert(0) += 1;
                
                // (ip_dst, protocol) : counter
                if let Some(ip_dst) = ip_dst {
                    *packet_map_infos.ip_dst_and_protocol.entry((ip_dst.clone(), protocol_4.clone())).or_insert(0) += 1;
                }

                if let Some(port_src) = packet.get_port_src() {
                    *packet_map_infos.port_srcs.entry(port_src.clone()).or_insert(0) += 1;
                }
                if let Some(port_dst) = packet.get_port_dst() {
                    *packet_map_infos.port_dsts.entry(port_dst.clone()).or_insert(0) += 1;
                    if let Some(ip_src) = ip_src {
                        let vec = packet_map_infos.ip_src_port_dsts
                            .entry(ip_src.clone())
                            .or_insert_with(Vec::new);

                        if !vec.contains(port_dst) {
                            vec.push(port_dst.clone());
                        }

                    }
                }
                if let Some(tcp_flags) = packet.get_tcp_flags() {
                    *packet_map_infos.tcp_flags.entry(tcp_flags).or_insert(0) += 1;
                }
            }
            packet_map_infos.set_ready();
        }
    }

    pub fn get_packet(&mut self, uuid: Uuid) -> Option<&PacketInfos> {
        self.packets.get(&uuid)
    }

}

pub fn start_cleaner_thread(packet_map: Arc<Mutex<PacketMap>>, packet_map_infos: Arc<(Mutex<PacketMapInfo>, Condvar)>) -> JoinHandle<()> {
    thread::spawn(move || {
        println!("cleaner thread starting");
        loop {
            {   
                let (packet_map_infos_mutex, condvar) = &*packet_map_infos;
                {
                    
                    let mut packet_map_infos = packet_map_infos_mutex.lock().unwrap();
                    packet_map_infos.clear();
                }
                let mut packet_map = packet_map.lock().unwrap();
                packet_map.get_statistics(packet_map_infos.clone());
                // {
                //     let packet_map_infos = packet_map_infos_mutex.lock().unwrap();
                //     // println!("{}", packet_map_infos);
                // }
                packet_map.cleanup_old_packets(0);
                // println!("{}", packet_map);
                condvar.notify_all();
            }
            thread::sleep(Duration::from_secs(2));
        }
    })
}

pub fn start_analyzer_thread(packet_map_infos: Arc<(Mutex<PacketMapInfo>, Condvar)>) -> JoinHandle<()> {
    thread::spawn(move || {
        println!("analyzer thread starting");
        let (packet_map_infos_mutex, condvar) = &*packet_map_infos;
        loop {
            { 
                let mut packet_map_infos = packet_map_infos_mutex.lock().unwrap();
                while !packet_map_infos.ready {
                packet_map_infos = condvar.wait(packet_map_infos).unwrap();
                }
                packet_map_infos.analyze();
            }
        }
    })
}

impl fmt::Display for PacketMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        for (uuid, packet_info) in self.packets.iter(){
            let datetime: DateTime<Utc> = (*packet_info.received_time()).into();
            let datetime = datetime.with_timezone(&Local);
            writeln!(f, "Packet ID: {}, {}", uuid, datetime.format("%d/%m/%Y %T"))?;
            // writeln!(f, "Packet Info: {}", packet_info)?;
            // writeln!(f, "-----------------------")?;
        }
        Ok(())
    }
}