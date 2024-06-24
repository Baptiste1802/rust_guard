use pnet::packet::{
    arp::{Arp, ArpOperation, ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, ipv4::{self, Ipv4Packet}, ipv6::Ipv6Packet, Packet
};
use pnet::packet::icmp::{Icmp, IcmpCode, IcmpPacket, IcmpType};
use pnet::util::MacAddr;
use std::{fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}, process};

#[derive(Clone)]
pub enum Layer3Infos {
    IPV4(Ipv4Handler),
    IPV6(Ipv6Handler),
    ARP(ArpHandler),
    Default(UnsupportedProtocol)
}

impl Layer3Infos {
    pub fn get_next_level_protocol(&self) -> Option<IpNextHeaderProtocol> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => ipv4_handler.get_next_protocol(),
            Layer3Infos::IPV6(ipv6_handler) => ipv6_handler.get_next_protocol(),
            Layer3Infos::ARP(_) => None,
            Layer3Infos::Default(_) => None,
        }
    }

    pub fn get_encapsulated_infos(&self) -> Option<&EncapsulatedProtocolInfos> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => ipv4_handler.get_encapsulated_infos(),
            _ => None,
        }
    }

    pub fn get_ip_src(&self) -> Option<&IpAddr> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => Some(ipv4_handler.get_ip_src()),
            Layer3Infos::IPV6(ipv6_handler) => Some(ipv6_handler.get_ip_src()),
            Layer3Infos::ARP(arp_handler) => Some(arp_handler.get_ip_src()),
            Layer3Infos::Default(_) => None,
        }
    }

    pub fn get_ip_src_str(&self) -> Option<String> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => Some(ipv4_handler.get_ip_src().to_string()),
            Layer3Infos::IPV6(ipv6_handler) => Some(ipv6_handler.get_ip_src().to_string()),
            Layer3Infos::ARP(arp_handler) => Some(arp_handler.get_ip_src().to_string()),
            Layer3Infos::Default(_) => None,
        }
    }

    pub fn get_ip_dst(&self) -> Option<&IpAddr> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => Some(ipv4_handler.get_ip_dst()),
            Layer3Infos::IPV6(ipv6_handler) => Some(ipv6_handler.get_ip_dst()),
            Layer3Infos::ARP(arp_handler) => Some(arp_handler.get_ip_dst()),
            Layer3Infos::Default(_) => None,
        }
    }

    pub fn get_ip_dst_str(&self) -> Option<String> {
        match self {
            Layer3Infos::IPV4(ipv4_handler) => Some(ipv4_handler.get_ip_dst().to_string()),
            Layer3Infos::IPV6(ipv6_handler) => Some(ipv6_handler.get_ip_dst().to_string()),
            Layer3Infos::ARP(arp_handler) => Some(arp_handler.get_ip_dst().to_string()),
            Layer3Infos::Default(_) => None,
        }
    }

    pub fn get_arp_infos(&self) -> Option<(&IpAddr, &IpAddr, &MacAddr, &MacAddr, String)> {
        // made in a hurry
        match self {
            Layer3Infos::ARP(arp_handler) => Some(arp_handler.get_informations()),
            _ => None,
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

#[derive(Clone)]
pub struct UnsupportedProtocol {
    packet_type: String,
}

impl UnsupportedProtocol {
    pub fn new(packet_type: String) -> Self {
        Self { packet_type }
    }
}

pub trait HandlePacket {
    fn get_layer_3(data: &[u8]) -> (Option<Vec<u8>>, Layer3Infos);
}

pub trait GetInformations {
    fn get_ip_dst(&self) -> &IpAddr;
    fn get_ip_src(&self) -> &IpAddr;
    fn get_next_protocol(&self) -> Option<IpNextHeaderProtocol>;
    fn get_encapsulated_infos(&self) -> Option<&EncapsulatedProtocolInfos>;
}


#[derive(Clone)]
pub struct Ipv4Handler {
    ip_source: IpAddr,
    ip_destination: IpAddr,
    next_protocol: IpNextHeaderProtocol,
    encapsulated_packet: Option<EncapsulatedProtocolInfos>,
}

impl HandlePacket for Ipv4Handler {
    fn get_layer_3<'a>(data: &[u8]) -> (Option<Vec<u8>>, Layer3Infos) {
        let ipv4_packet = Ipv4Packet::new(data).unwrap_or_else(|| {
            eprintln!("Invalid IPv4 packet");
            process::exit(1);
        });

        let protocol = ipv4_packet.get_next_level_protocol();        

        let layer_3_infos = Layer3Infos::IPV4(Ipv4Handler {
            ip_source: IpAddr::V4(ipv4_packet.get_source()),
            ip_destination: IpAddr::V4(ipv4_packet.get_destination()),
            next_protocol: protocol,
            encapsulated_packet: extract_encapsalted_protocol(protocol, data)
        });
        (Some(ipv4_packet.payload().to_vec()), layer_3_infos)
    }
}

impl GetInformations for Ipv4Handler {
    fn get_ip_src(&self) -> &IpAddr {
        &self.ip_source
    }

    fn get_ip_dst(&self) -> &IpAddr {
        &self.ip_destination
    }

    fn get_next_protocol(&self) -> Option<IpNextHeaderProtocol> {
        if self.encapsulated_packet.is_some() {
            return None
        }
        Some(self.next_protocol)
    }

    fn get_encapsulated_infos(&self) -> Option<(&EncapsulatedProtocolInfos)> {
        match self.next_protocol {
            IpNextHeaderProtocols::Icmp => {
                if let Some(encapsulated_packet) = self.encapsulated_packet.as_ref() {
                    return Some(encapsulated_packet)
                }
                None
            } 
            _ => None
        }
    }
}

#[derive(Clone)]
pub struct Ipv6Handler {
    ip_source: IpAddr,
    ip_destination: IpAddr,
    next_protocol: IpNextHeaderProtocol
}

impl HandlePacket for Ipv6Handler {
    fn get_layer_3(data: &[u8]) -> (Option<Vec<u8>>, Layer3Infos) {
        let ipv6_packet = Ipv6Packet::new(data).unwrap_or_else(|| {
            eprintln!("Invalid IPv6 packet");
            process::exit(1);
        });

        let layer_3_infos = Layer3Infos::IPV6(Ipv6Handler {
            ip_source: IpAddr::V6(ipv6_packet.get_source()),
            ip_destination: IpAddr::V6(ipv6_packet.get_destination()),
            next_protocol: ipv6_packet.get_next_header()
        });

        (Some(ipv6_packet.payload().to_vec()), layer_3_infos)
    }

}

impl GetInformations for Ipv6Handler {
    fn get_ip_src(&self) -> &IpAddr {
        &self.ip_source
    }

    fn get_ip_dst(&self) -> &IpAddr {
        &self.ip_destination
    }

    fn get_next_protocol(&self) -> Option<IpNextHeaderProtocol> {
        Some(self.next_protocol)
    }
    
    fn get_encapsulated_infos(&self) -> Option<&EncapsulatedProtocolInfos> {
        None
    }
}

#[derive(Clone)]
pub struct ArpHandler {
    pub ip_source: IpAddr,
    pub ip_destination: IpAddr,
    pub hw_source: MacAddr,
    pub hw_destination: MacAddr,
    pub operation: ArpOperation,
}

impl HandlePacket for ArpHandler {
    fn get_layer_3(data: &[u8]) -> (Option<Vec<u8>>, Layer3Infos) {
        let arp_packet = ArpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid ARP packet");
            process::exit(1);
        });

        let layer_3_infos = Layer3Infos::ARP(ArpHandler {
            ip_source: IpAddr::V4(arp_packet.get_sender_proto_addr()),
            ip_destination: IpAddr::V4(arp_packet.get_target_proto_addr()),
            hw_source: arp_packet.get_sender_hw_addr(),
            hw_destination: arp_packet.get_target_hw_addr(),
            operation: arp_packet.get_operation()
        });

        (None, layer_3_infos)
    }
}

impl ArpHandler {

    pub fn operation_to_str(&self) -> String{
        match self.operation {
            ArpOperations::Reply => "is-at".to_string(),
            ArpOperations::Request => "who-has".to_string(),
            _ => "unknown".to_string(),
        }
    }
    pub fn get_informations(&self) -> (&IpAddr, &IpAddr, &MacAddr, &MacAddr, String){
        (&self.ip_source, &self.ip_destination, &self.hw_source, &self.hw_destination, self.operation_to_str())
    }
}

impl GetInformations for ArpHandler {
    fn get_ip_src(&self) -> &IpAddr {
        &self.ip_source
    }

    fn get_ip_dst(&self) -> &IpAddr {
        &self.ip_destination
    }

    fn get_encapsulated_infos(&self) -> Option<&EncapsulatedProtocolInfos> {
        None
    }

    fn get_next_protocol(&self) -> Option<IpNextHeaderProtocol> {
        None
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

pub fn extract_encapsalted_protocol(ip_next_header_protocol: IpNextHeaderProtocol, data: &[u8]) -> Option<EncapsulatedProtocolInfos>{
    match ip_next_header_protocol {
        IpNextHeaderProtocols::Icmp => Some(ICMPHandler::get_informations(data)), 
        _ => None,
    }
}

#[derive(Clone)]
pub enum EncapsulatedProtocolInfos {
    ICMP(ICMPHandler)
}

pub trait HandleEncapsulatedPacket {
    fn get_informations(data: &[u8]) -> EncapsulatedProtocolInfos;
}

#[derive(Clone)]
pub struct ICMPHandler {
    icmp_type: IcmpType,
    icmp_code: IcmpCode,
    checksum: u16,
}

impl ICMPHandler {
    pub fn get_data(&self) -> (&IcmpType, &IcmpCode, &u16){
        (&self.icmp_type, &self.icmp_code, &self.checksum)
    }
}

impl HandleEncapsulatedPacket for ICMPHandler {
    fn get_informations(data: &[u8]) -> EncapsulatedProtocolInfos {
        let icmp_packet = IcmpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid ICMP packet");
            process::exit(1);
        });
    
        EncapsulatedProtocolInfos::ICMP(ICMPHandler {
            icmp_code: icmp_packet.get_icmp_code(),
            icmp_type: icmp_packet.get_icmp_type(),
            checksum: icmp_packet.get_checksum()
        })
    }
}
