use pnet::packet::{
    arp::{ArpOperation, ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocol, ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet
};
use std::{process, fmt};

pub enum Layer3Infos {
    IPV4(Ipv4Handler),
    IPV6(Ipv6Handler),
    ARP(ArpHandler),
    Default(UnsupportedProtocol)
}

impl  Layer3Infos {
    pub fn get_next_level_protocol(&self) -> Option<IpNextHeaderProtocol> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => Some(ipv4_handler.next_protocol),
            Layer3Infos::IPV6(ipv6_handler) => Some(ipv6_handler.next_protocol),
            Layer3Infos::ARP(_) => None,
            Layer3Infos::Default(_) => None,
        }
    }
}

impl fmt::Display for Layer3Infos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer3Infos::ARP(arp) => write!(f, "{}", arp)?,
            Layer3Infos::IPV4(ipv4) => write!(f, "{}", ipv4)?,
            Layer3Infos::IPV6(ipv6) => write!(f, "{}", ipv6)?,
            Layer3Infos::Default(unknown) => write!(f, "Unknown layer 3 protocol: {}\n", unknown.packet_type)?,
        }
        Ok(())
    }   
}

pub struct UnsupportedProtocol {
    packet_type: String,
}

impl UnsupportedProtocol {
    pub fn new(packet_type: String) -> Self {
        Self { packet_type }
    }
}

pub trait HandlePacket {
    fn get_layer_3(data: &[u8]) -> Layer3Infos;
}


pub struct Ipv4Handler {
    ip_source: String,
    ip_destination: String,
    next_protocol: IpNextHeaderProtocol
}

impl HandlePacket for Ipv4Handler {
    fn get_layer_3(data: &[u8]) -> Layer3Infos {
        let ipv4_packet = Ipv4Packet::new(data).unwrap_or_else(|| {
            eprintln!("Invalid IPv4 packet");
            process::exit(1);
        });

        Layer3Infos::IPV4(Ipv4Handler {
            ip_source: ipv4_packet.get_source().to_string(),
            ip_destination: ipv4_packet.get_destination().to_string(),
            next_protocol: ipv4_packet.get_next_level_protocol()
        })
    }
}

pub struct Ipv6Handler {
    ip_source: String,
    ip_destination: String,
    next_protocol: IpNextHeaderProtocol
}

impl HandlePacket for Ipv6Handler {
    fn get_layer_3(data: &[u8]) -> Layer3Infos {
        let ipv6_packet = Ipv6Packet::new(data).unwrap_or_else(|| {
            eprintln!("Invalid IPv6 packet");
            process::exit(1);
        });

        Layer3Infos::IPV6(Ipv6Handler {
            ip_source: ipv6_packet.get_source().to_string(),
            ip_destination: ipv6_packet.get_destination().to_string(),
            next_protocol: ipv6_packet.get_next_header()
        })
    }
}


pub struct ArpHandler {
    ip_source: String,
    ip_destination: String,
    hw_source: String,
    hw_destination: String,
    operation: ArpOperation,
}

impl HandlePacket for ArpHandler {
    fn get_layer_3(data: &[u8]) -> Layer3Infos {
        let arp_packet = ArpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid ARP packet");
            process::exit(1);
        });

        Layer3Infos::ARP(ArpHandler {
            ip_source: arp_packet.get_sender_proto_addr().to_string(),
            ip_destination: arp_packet.get_target_proto_addr().to_string(),
            hw_source: arp_packet.get_sender_hw_addr().to_string(),
            hw_destination: arp_packet.get_target_hw_addr().to_string(),
            operation: arp_packet.get_operation()
        })
    }
}

impl fmt::Display for Ipv4Handler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "- IPsrc: {}\n- IPdst: {}", self.ip_source, self.ip_destination)?;
        Ok(())
    }   
}

impl fmt::Display for Ipv6Handler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "- IPsrc: {}\n- IPdst: {}", self.ip_source, self.ip_destination)?;
        Ok(())
    }   
}

impl fmt::Display for ArpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.operation {
            ArpOperations::Reply => write!(f, "- Operation is-at (reply)\n")?,
            ArpOperations::Request => write!(f, "- Operation who-as (request)\n")?,
            _ => write!(f, "- Unknown Operation\n")?,
        }   
        write!(f, "- IPsrc: {}\n- IPdst: {}\n- MACsrc: {}\n- MACdst: {}", 
        self.ip_source,
        self.ip_destination,
        self.hw_source,
        self.hw_destination 
        )?;
        Ok(())
    }
}