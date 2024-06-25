mod api;
use api::arp_cache::ArpCache;
use api::packet_infos::{PacketInfos, start_thread_handling_packets};
use api::config::load_config;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, interfaces};
use std::time::Duration;
use pnet::packet::ethernet::EthernetPacket;
use std::sync::{Arc, Mutex, Condvar};
use crossbeam::channel::{unbounded, Sender, Receiver};

use crate::api::packet_map::{start_cleaner_thread, start_analyzer_thread};



fn main() -> std::io::Result<()> {

    let app_config = Arc::new(load_config("./src/config.json"));

    println!("IP Whitelisted {:?}\nPorts Whitelisted {:?}\nHoneyPot Port{}", app_config.get_whitelisted_ips(), app_config.get_whitelisted_ports() ,app_config.get_honeypot_port());


    let packet_map_info = Arc::new((Mutex::new(api::packet_map::PacketMapInfo::new()), Condvar::new()));
    let packet_map = Arc::new(Mutex::new(api::packet_map::PacketMap::new()));

    let (sender, receiver): (Sender<(PacketInfos, u64)>, Receiver<(PacketInfos, u64)>) = unbounded();
    let receiver = Arc::new(receiver);
    let cpus = num_cpus::get() - 2;

    for thread_id in 0..cpus {
        let receiver = receiver.clone();
        start_thread_handling_packets(receiver, app_config.clone(), thread_id)
    }

    // return a vector with all newtork interfaces found
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

    println!("default interface {}", default_interface);

    let _cleaner_thread = start_cleaner_thread(packet_map.clone(), packet_map_info.clone());

    let _analyzer_thread = start_analyzer_thread(packet_map_info.clone());

    let (_, mut rx) = match datalink::channel(&default_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}", &default_interface),
        Err(e) => panic!("An error occured when creating the datalink channel: {}", e)
    };
    let mut cache_arp = ArpCache::new(Duration::new(600, 0),default_interface);

    println!("Start reading packet on iface {}.", default_interface.name);
    let mut i: u64 = 0;
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let packet_info: PacketInfos = api::packet_infos::PacketInfos::new(&default_interface.name, &ethernet_packet);
                    cache_arp.network_verification(&packet_info);
                    
                    // println!("{}", packet_info);
                    // println!("PACKET RECEIPT {}", i);
                    let _ = sender.send((packet_info.clone(), i));
                    {
                        let mut packet_map = packet_map.lock().unwrap();
                        packet_map.add_packet(packet_info);
                    }
                    i += 1;
                }
            },
            Err(e) => {
                panic!("An error occured while reading: {}", e);
            }
        }
    };

}






















































