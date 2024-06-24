use std::fmt;
use thiserror::Error;
use chrono;

#[derive(Error,Debug,PartialEq)]
pub enum ArpCacheError{
    #[error("Invalid Ip Source : {ip_source:?}")]
    InvalidIpSource{
        ip_source: String,
    },
    #[error("IP not in subnet : {ip:?}")]
    SubnetError{
        ip : String,
    },
    #[error("MacAddr source is broadcast : {mac:?}")]
    HwBroadError{
        mac : String,
    },
    #[error("MacAddr in ehternet packet do not correspond to MacAddr in ARP paclet : {macEther:?} != {macARP:?}")]
    HwEtherArpError{
        macEther: String,
        macARP: String,
    },
    #[error("Duplicated IP or MAC address detected ({ip:?}/{mac:?})")]
    SpoofingAlert{
        ip: String,
        mac : String,
    },
    #[error("Fatal network error")]
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



pub fn log_error(err : dyn Error){
    let date_time = chrono::offset::Local::now();
   
    


}