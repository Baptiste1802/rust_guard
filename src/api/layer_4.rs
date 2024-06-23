use pnet::packet::{ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, tcp::TcpPacket, udp::Udp};
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpFlags;
use std::{fmt, process, vec};

#[derive(Clone)]
pub enum Layer4Infos {
    TCP(TcpHandler),
    UDP(UdpHandler),
    Default(UnsupportedProtocol4),
}

impl Layer4Infos {
    pub fn get_port_src(&self) -> Option<&String> {
        match self {
            Layer4Infos::TCP(tcp_handler) => Some(tcp_handler.get_port_src()),
            Layer4Infos::UDP(udp_handler) => Some(udp_handler.get_port_src()),
            Layer4Infos::Default(_) => None,
        }
    }

    pub fn get_port_dst(&self) -> Option<&String> {
        match self {
            Layer4Infos::TCP(tcp_handler) => Some(tcp_handler.get_port_dst()),
            Layer4Infos::UDP(udp_handler) => Some(udp_handler.get_port_dst()),
            Layer4Infos::Default(_) => None,
        }
    }

    pub fn get_tcp_flags(&self) -> Option<Vec<String>> {
        match self {
            Layer4Infos::TCP(tcp_handler) => Some(tcp_handler.get_tcp_flags(tcp_handler.get_flags())),
            _ => None
        } 
    }
}



#[derive(Clone)]
pub struct TcpHandler {
    port_source: String,
    port_destination: String,
    flags: u8,
}

#[derive(Clone)]
pub struct UdpHandler {
    port_source: String,
    port_destination: String
}

#[derive(Clone)]
pub struct UnsupportedProtocol4 {
    protocol: String
}

impl UnsupportedProtocol4 {
    pub fn new(protocol: String) -> Self {
        Self { protocol }
    }
}

impl fmt::Display for Layer4Infos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer4Infos::TCP(tcp_packet) => write!(f, "{}", tcp_packet)?,
            Layer4Infos::UDP(udp_packet) => write!(f, "{}", udp_packet)?,
            Layer4Infos::Default(unknown) => write!(f, "Unknown layer 4 protocol: {}", unknown.protocol)?,
        }
        Ok(())
    }
}

pub trait HandlePacket4 {
    fn get_layer_4(data: &[u8]) -> Layer4Infos;
}

pub trait GetInformations4 {
    fn get_port_src(&self) -> &String;
    fn get_port_dst(&self) -> &String;
}

impl TcpHandler {
    pub fn get_flags(&self) -> &u8 {
        &self.flags
    }
    pub fn get_tcp_flags(&self, data: &u8) -> Vec<String> {
        let mut v = Vec::with_capacity(8);
        if TcpFlags::CWR & data != 0 {
            v.push("CWR".to_string());
        }
        if TcpFlags::ECE & data != 0 {
            v.push("ECE".to_string());
        }
        if TcpFlags::URG & data != 0 {
            v.push("URG".to_string());
        }
        if TcpFlags::ACK & data != 0 {
            v.push("ACK".to_string());
        }
        if TcpFlags::PSH & data != 0 {
            v.push("PSH".to_string());
        }
        if TcpFlags::RST & data != 0 {
            v.push("RST".to_string());
        }
        if TcpFlags::SYN & data != 0 {
            v.push("SYN".to_string());
        }
        if TcpFlags::FIN & data != 0 {
            v.push("FIN".to_string());
        }
        v
    }
}

impl HandlePacket4 for TcpHandler {

    fn get_layer_4(data: &[u8]) -> Layer4Infos {

        let tcp_packet = TcpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid TCP packet");
            process::exit(1);
        });

        Layer4Infos::TCP(TcpHandler {
            port_source: tcp_packet.get_source().to_string(),
            port_destination: tcp_packet.get_destination().to_string(),
            flags: tcp_packet.get_flags(),
        })
    }
}

impl GetInformations4 for TcpHandler {
    fn get_port_src(&self) -> &String {
        &self.port_source
    }
    fn get_port_dst(&self) -> &String {
        &self.port_destination
    }
}

impl fmt::Display for TcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, " - PORTsrc: {}\n - PORTdst: {}\n, -FLAGS: {:?}\n", self.port_source, self.port_destination, self.get_tcp_flags(&self.flags))?;
        Ok(())
    }
}

impl HandlePacket4 for UdpHandler {

    fn get_layer_4(data: &[u8]) -> Layer4Infos {
        let udp_packet = UdpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid UDP packet");
            process::exit(1);
        });

        Layer4Infos::UDP(UdpHandler {
            port_source: udp_packet.get_source().to_string(),
            port_destination: udp_packet.get_destination().to_string(),
        })
    }
}

impl GetInformations4 for UdpHandler {
    fn get_port_src(&self) -> &String {
        &self.port_source
    }
    fn get_port_dst(&self) -> &String {
        &self.port_destination
    }
}

impl fmt::Display for UdpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, " - PORTsrc: {}\n - PORTdst: {}\n", self.port_source, self.port_destination)?;
        Ok(())
    }
}

pub fn get_layer_4_infos(protocol: IpNextHeaderProtocol, data: &[u8]) -> Layer4Infos {
    match protocol {
        IpNextHeaderProtocols::Tcp => TcpHandler::get_layer_4(data),
        IpNextHeaderProtocols::Udp => UdpHandler::get_layer_4(data),
        _ => Layer4Infos::Default(UnsupportedProtocol4::new("Unknown".to_string())),
    }
}




