mod api;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, interfaces};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{self, Packet};
use std::thread::sleep;
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};

use crate::api::packet_map::{self, start_cleaner_thread};

fn main() -> std::io::Result<()> {


    let packet_map = Arc::new(Mutex::new(api::packet_map::PacketMap::new()));
    let cleaner_thread = start_cleaner_thread(packet_map.clone());

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

    let (_, mut rx) = match datalink::channel(&default_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}", &default_interface),
        Err(e) => panic!("An error occured when creating the datalink channel: {}", e)
    };

    println!("Start reading packet on iface {}.", default_interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let packet_info = api::packet_infos::PacketInfos::new(&default_interface.name, &ethernet_packet);
                    // println!("{}", packet_info);
                    {
                        let mut packet_map = packet_map.lock().unwrap();
                        packet_map.add_packet(packet_info);
                    }
                }
            },
            Err(e) => {
                panic!("An error occured while reading: {}", e);
            }
        }

    };


}






















































