use crate::api::layer_3::*;
use crate::api::layer_4::*;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::icmp_packet_iter;
use pnet::util::MacAddr;
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    Packet,
};
use std::time::SystemTime;
use chrono::offset::Utc;
use chrono::{DateTime, Local, TimeZone};

#[derive(Clone)]
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
    pub fn new(interface_name: &String, ethernet_packet: &EthernetPacket) -> PacketInfos {
        
        let interface = interface_name.to_string();
        let mac_address_source = ethernet_packet.get_source();
        let mac_address_destination = ethernet_packet.get_destination();
        let layer_3_protocol = ethernet_packet.get_ethertype().to_string();
        let (payload, layer_3_infos) = get_layer_3_infos(ethernet_packet);
        
        // on récupère le protocol 4 si on est en présence d'un paquet IPv4 ou IPv6
        let layer_4_protocol = layer_3_infos.get_next_level_protocol();
        
        let layer_4_infos = match (layer_4_protocol, payload) {
            (Some(protocol), Some(data)) => {
                Some(get_layer_4_infos(protocol, data.as_slice()))
            }
            _ => None,
        };
        
        // let layer_4_infos = layer_4_protocol.map( | value | get_layer_4_infos(value, payload));

        // on override la variable layer_4_protocol
        let layer_4_protocol = match layer_4_protocol {
            Some(IpNextHeaderProtocols::Tcp) => Some(String::from("TCP")),
            Some(IpNextHeaderProtocols::Udp) => Some(String::from("UDP")),
            Some(_) => Some(String::from("Unsupported")),
            None => None
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

    pub fn get_mac_source(&self) -> &MacAddr {
        &self.mac_address_source
    }

    pub fn get_mac_destination(&self) -> &MacAddr {
        &self.mac_address_destination
    }

    pub fn get_string_protocol_3(&self) -> &String {
        &self.layer_3_protocol
    }

    pub fn get_layer_3_handler(&self) -> &Layer3Infos {
        &self.layer_3_infos
    }

    pub fn get_ip_src(&self) -> Option<&String> {
        self.layer_3_infos.get_ip_src()
    }

    pub fn get_ip_dst(&self) -> Option<&String> {
        self.layer_3_infos.get_ip_dst()
    }

    pub fn get_string_protocol_4(&self) -> &Option<String> {
        &self.layer_4_protocol
    }

    pub fn get_port_src(&self) -> Option<&String> {
        if let Some(ref layer_4_infos) = self.layer_4_infos {
            layer_4_infos.get_port_src()
        } else {
            None
        }
    }

    pub fn get_port_dst(&self) -> Option<&String> {
        if let Some(ref layer_4_infos) = self.layer_4_infos {
            layer_4_infos.get_port_dst()
        } else {
            None
        }
    }

    pub fn get_tcp_flags(&self) -> Option<Vec<String>> {
        if let Some(ref layer_4_infos) = self.layer_4_infos {
            layer_4_infos.get_tcp_flags()
        } else {
            None
        }
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
        write!(f, "EtherType: {}\n", self.layer_3_protocol)?;
        write!(f, "{}\n", self.layer_3_infos)?;
        if let Some(encapsulated_packet) = self.layer_3_infos.get_encapsulated_infos() {
            match encapsulated_packet {
                EncapsulatedProtocolInfos::ICMP(icmp_packet) => {
                    let (icmp_type, icmp_code, icmp_checksum) = icmp_packet.get_data();
                    write!(f, "ICMP packet type: {:?}, code: {:?}, checksum: {}\n", icmp_type, icmp_code, icmp_checksum)?;
                }
            }
        }
        if let Some(layer_4_protocol) = self.layer_4_protocol.as_ref() {
            write!(f, "IpNextHeaderProtocol: {}\n", layer_4_protocol)?;
        }
        
        if let Some(layer_4_infos) = self.layer_4_infos.as_ref() {
            write!(f, "{}\n", layer_4_infos)?;
        }
        Ok(())
    }
}

pub fn get_layer_3_infos(ethernet_packet: &EthernetPacket) -> (Option<Vec<u8>>, Layer3Infos) {
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv6 => Ipv6Handler::get_layer_3(ethernet_packet.payload()),
        EtherTypes::Ipv4 => Ipv4Handler::get_layer_3(ethernet_packet.payload()),
        EtherTypes::Arp => ArpHandler::get_layer_3(ethernet_packet.payload()),
        _ => (None, Layer3Infos::Default(UnsupportedProtocol::new(ethernet_packet.get_ethertype().to_string()))),
    }
}

