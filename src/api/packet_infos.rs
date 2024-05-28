use crate::api::layer_3::*;
use crate::api::layer_4::*;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    Packet,
};
use std::time::SystemTime;
use chrono::offset::Utc;
use chrono::{DateTime, Local, TimeZone};

pub struct PacketInfos {
    received_time: SystemTime,
    mac_address_source: MacAddr,
    mac_address_destination: MacAddr,
    interface: String,
    layer_3_protocol: String,
    layer_3_infos: Layer3Infos,
    layer_4_protocol: Option<String>,
    layer_4_infos: Option<Layer4Infos>,
}

impl PacketInfos {
    // Constructor method to create a new PacketInfos object
    pub fn new(interface_name: &String, ethernet_packet: &EthernetPacket) -> PacketInfos {
        // Inside the constructor, we initialize the object's fields
        
        let interface = interface_name.to_string();
        let mac_address_source = ethernet_packet.get_source();
        let mac_address_destination = ethernet_packet.get_destination();
        let layer_3_protocol = ethernet_packet.get_ethertype().to_string();
        let layer_3_infos = get_layer_3_infos(ethernet_packet);
        let layer_4_protocol = layer_3_infos.get_next_level_protocol();
        let layer_4_infos = if Some(layer_4_protocol).is_some() {
            get_layer_4_infos(layer_4_protocol, ethernet_packet.payload())
        } else {
            None
        };

        let layer_4_protocol = match layer_4_protocol {
            Some(IpNextHeaderProtocols::Tcp) => Some(String::from("TCP")),
            Some(IpNextHeaderProtocols::Udp) => Some(String::from("UDP")),
            Some(_) => Some(String::from("Unknown")),
            None => None,
        };
        
        PacketInfos {
            received_time: SystemTime::now(),
            mac_address_source,
            mac_address_destination,
            interface: interface,
            layer_3_protocol,
            layer_3_infos,
            layer_4_protocol,
            layer_4_infos,
        }
    }

    pub fn received_time(&self) -> &SystemTime {
        &self.received_time
    }


    pub fn get_layer_3_infos(&self) -> &Layer3Infos{
        &self.layer_3_infos
    }

    pub fn get_sender_hw_addr(&self) -> &MacAddr{
        &self.mac_address_source
    }
}

use std::fmt;

impl fmt::Display for PacketInfos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let datetime: DateTime<Utc> = self.received_time.into();
        let datetime = datetime.with_timezone(&Local);
        write!(f, "Date: {}\n", datetime.format("%d/%m/%Y %T"))?;
        write!(f, "MAC Source: {}\n", self.mac_address_source)?;
        write!(f, "MAC Destination: {}\n", self.mac_address_destination)?;
        write!(f, "Interface: {}\n", self.interface)?;
        // Format other fields as needed
        write!(f, "EtherType: {}\n", self.layer_3_protocol)?;
        write!(f, "{}\n", self.layer_3_infos)?;
        if let Some(layer_4_protocol) = self.layer_4_protocol.as_ref() {
            write!(f, "IpNextHeaderProtocol: {}\n", layer_4_protocol)?;
        }
        
        if let Some(layer_4_infos) = self.layer_4_infos.as_ref() {
            write!(f, "{}\n", layer_4_infos)?;
        }
        Ok(())
    }
}

pub fn get_layer_3_infos(ethernet_packet: & EthernetPacket) -> Layer3Infos {
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv6 => Ipv6Handler::get_layer_3(ethernet_packet.payload()),
        EtherTypes::Ipv4 => Ipv4Handler::get_layer_3(ethernet_packet.payload()),
        EtherTypes::Arp => ArpHandler::get_layer_3(ethernet_packet.payload()),
        _ => Layer3Infos::Default(UnsupportedProtocol::new(ethernet_packet.get_ethertype().to_string())),
    }
}

