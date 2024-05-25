use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use uuid::{uuid, Uuid};
use chrono::offset::Utc;
use chrono::{DateTime, Local, TimeZone};

use super::packet_infos::PacketInfos;

pub struct PacketMap {
    packets: HashMap<Uuid, PacketInfos>
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


use std::fmt;

impl fmt::Display for PacketMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (uuid, packet_info) in &self.packets {
            let datetime: DateTime<Utc> = (*packet_info.received_time()).into();
            let datetime = datetime.with_timezone(&Local);
            writeln!(f, "Packet ID: {}, {}", uuid, datetime.format("%d/%m/%Y %T"))?;
            // writeln!(f, "Packet Info: {}", packet_info)?;
            // writeln!(f, "-----------------------")?;
        }
        Ok(())
    }
}