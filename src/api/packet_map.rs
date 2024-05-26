use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use uuid::{uuid, Uuid};
use chrono::offset::Utc;
use chrono::{DateTime, Local, TimeZone};
use std::thread::{self, JoinHandle};
use std::sync::{Arc, Mutex};

use super::packet_infos::{self, PacketInfos};

pub struct PacketMap {
    packets:  HashMap<Uuid, PacketInfos>,
}

impl PacketMap {
    pub fn new() -> Self {
        PacketMap {
            packets: HashMap::new(),
        }
    }

    pub fn add_packet(&mut self, packet: PacketInfos) {
        let id = Uuid::new_v4();
        self.packets.insert(id, packet);
    }

    pub fn cleanup_old_packets(&mut self, secs: u64) {
        let now = SystemTime::now();
        let datetime: DateTime<Utc> = now.into();
        let datetime = datetime.with_timezone(&Local);
        println!("Now: {}",  datetime.format("%d/%m/%Y %T") );
        let duration = now - Duration::from_secs(secs);
        let datetime: DateTime<Utc> = duration.into();
        let datetime = datetime.with_timezone(&Local);
        println!("duration: {}", datetime.format("%d/%m/%Y %T"));


        let old_packets: Vec<Uuid> = self.packets.iter()
            .filter(|(_, packet)| packet.received_time() < &duration)
            .map(|(id, _)| *id)
            .collect();

        for id in old_packets {
            self.packets.remove(&id);
        }
    }

    pub fn get_packet(&mut self, uuid: Uuid) -> Option<&PacketInfos> {
        self.packets.get(&uuid)
    }

}


pub fn start_cleaner_thread(packet_map: Arc<Mutex<PacketMap>>) -> JoinHandle<()> {
    thread::spawn(move || {
        println!("thread starting");
        loop {
            {   
                let mut packet_map = packet_map.lock().unwrap();
                println!("-------------------- BEFORE --------------------");
                println!("{}", packet_map);
                println!("----------------------------------------");
                println!("cleaning");
                packet_map.cleanup_old_packets(60);
                println!("-------------------- AFTER --------------------");
                println!("{}", packet_map);
                println!("----------------------------------------");
            }
            thread::sleep(Duration::from_secs(5));
        }
    })
}


use std::fmt;

impl fmt::Display for PacketMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        for (uuid, packet_info) in self.packets.iter(){
            let datetime: DateTime<Utc> = (*packet_info.received_time()).into();
            let datetime = datetime.with_timezone(&Local);
            writeln!(f, "Packet ID: {}, {}", uuid, datetime.format("%d/%m/%Y %T"))?;
            // writeln!(f, "Packet Info: {}", packet_info)?;
            // writeln!(f, "-----------------------")?;
        }
        Ok(())
    }
}