use std::{fmt, fs::OpenOptions, io::Write};
use thiserror::Error;
use chrono;
use std::error::Error;
#[derive(Error,Debug,PartialEq)]
pub enum ArpCacheError{
    #[error("ARP cache -> Invalid Ip Source : {ip_source:?}")]
    InvalidIpSource{
        ip_source: String,
    },
    #[error("ARP cache -> IP not in subnet : {ip:?}")]
    SubnetError{
        ip : String,
    },
    #[error("ARP cache -> MacAddr source is broadcast : {mac:?}")]
    HwBroadError{
        mac : String,
    },
    #[error("ARP cache -> MacAddr in ehternet packet do not correspond to MacAddr in ARP paclet : {macEther:?} != {macARP:?}")]
    HwEtherArpError{
        macEther: String,
        macARP: String,
    },
    #[error("ARP cache -> Duplicated IP or MAC address detected ({ip:?}/{mac:?})")]
    SpoofingAlert{
        ip: String,
        mac : String,
    },
    #[error("ARP cache -> Fatal network error")]
    NetworkError,
}


// impl fmt::Display for ArpCacheError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
//         match *self{
//             ArpCacheError::NetworkError => write!(f,"Invalid parameters in ARP paquet"),
//             ArpCacheError::SpoofingAlert => write!(f,"Ip/Mac pair already exist in cache")
//         }
//     }
// }



pub fn log_error(err : &dyn Error){
    let date_time = chrono::offset::Local::now();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("error_log.txt")
        .expect("Unable to open or create log file");

    let log_entry = format!("[{}] {}\n", date_time, err);

    file .write_all(log_entry.as_bytes()).expect("Unable to write to log file");


    
}