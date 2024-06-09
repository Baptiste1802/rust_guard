use pnet::packet::{ip::{IpNextHeaderProtocols, IpNextHeaderProtocol}, tcp::TcpPacket};
use pnet::packet::udp::UdpPacket;
use std::{process, fmt};



pub enum Layer4Infos {
    TCP(TcpHandler),
    UDP(UdpHandler),
    Default(UnsupportedProtocol4),
}

pub struct TcpHandler {
    port_source: String,
    port_destination: String
}

pub struct UdpHandler {
    port_source: String,
    port_destination: String
}

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

impl HandlePacket4 for TcpHandler {

    fn get_layer_4(data: &[u8]) -> Layer4Infos {
        let tcp_packet = TcpPacket::new(data).unwrap_or_else(|| {
            eprintln!("Invalid TCP packet");
            process::exit(1);
        });

        Layer4Infos::TCP(TcpHandler {
            port_source: tcp_packet.get_source().to_string(),
            port_destination: tcp_packet.get_destination().to_string(),
        })
    }
}

impl fmt::Display for TcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, " - PORTsrc: {}\n - PORTdst: {}\n", self.port_source, self.port_destination)?;
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

impl fmt::Display for UdpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, " - PORTsrc: {}\n - PORTdst: {}\n", self.port_source, self.port_destination)?;
        Ok(())
    }
}

pub fn get_layer_4_infos(protocol: Option<IpNextHeaderProtocol>, data: &[u8]) -> Option<Layer4Infos> {
    match protocol {
        Some(IpNextHeaderProtocols::Tcp) => Some(TcpHandler::get_layer_4(data)),
        Some(IpNextHeaderProtocols::Udp) => Some(UdpHandler::get_layer_4(data)),
        Some(_) => Some(Layer4Infos::Default(UnsupportedProtocol4::new("Unknown".to_string()))),
        None => None,
    }
}



