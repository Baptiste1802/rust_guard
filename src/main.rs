mod api;
use api::packet_infos::PacketInfos;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, interfaces};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{self, Packet};
use uuid::Uuid;
use std::thread::sleep;
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex, Condvar};
use crossbeam::channel::{unbounded, Sender, Receiver};

use crate::api::packet_map::{self, start_cleaner_thread, start_analyzer_thread};

fn process_packet(packet_info: &PacketInfos){
    thread::sleep(Duration::from_micros(10000));    
}

fn start_thread_handling_packets(receiver: Arc<Receiver<(PacketInfos, u64)>> , thread_id: usize){
    
    thread::spawn(move ||{
        loop {
            if let Ok((packet_info, uuid)) = receiver.recv() {
                process_packet(&packet_info);
            } else {
                thread::sleep(Duration::from_secs(1));
            }
        }
    });
    

}

fn main() -> std::io::Result<()> {

    let packet_map_info = Arc::new((Mutex::new(api::packet_map::PacketMapInfo::new()), Condvar::new()));
    let packet_map = Arc::new(Mutex::new(api::packet_map::PacketMap::new()));

    let (sender, receiver): (Sender<(PacketInfos, u64)>, Receiver<(PacketInfos, u64)>) = unbounded();
    let receiver = Arc::new(receiver);
    let cpus = num_cpus::get() - 2;

    for thread_id in 0..cpus {
        let receiver = receiver.clone();
        start_thread_handling_packets(receiver, thread_id)
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

    let cleaner_thread = start_cleaner_thread(packet_map.clone(), packet_map_info.clone());

    let analyzer_thread = start_analyzer_thread(packet_map_info.clone());

    let (_, mut rx) = match datalink::channel(&default_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}", &default_interface),
        Err(e) => panic!("An error occured when creating the datalink channel: {}", e)
    };

    println!("Start reading packet on iface {}.", default_interface.name);
    let mut i: u64 = 0;
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let packet_info: PacketInfos = api::packet_infos::PacketInfos::new(&default_interface.name, &ethernet_packet);
                    // println!("{}", packet_info);
                    // println!("PACKET RECEIPT {}", i);
                    sender.send((packet_info.clone(), i));
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






















































