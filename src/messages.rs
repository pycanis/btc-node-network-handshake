use std::{
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::utils::double_sha256;

use crate::{NODE_IP, NODE_PORT};

const MAGIC_BYTES: &str = "f9beb4d9";

pub fn parse_received_message(message: [u8; 1024], bytes_received: usize) -> String {
    println!("Bytes received: {}", bytes_received);

    println!("Message: {:?}", hex::encode(&message[0..bytes_received]));

    let command_bytes = &message[4..16];
    let command = String::from_utf8(command_bytes.to_vec()).expect("Error parsing command");

    let message_hex = match command.as_str() {
        "version" => parse_version_and_verack_message(message),
        &_ => hex::encode(&message[0..bytes_received]),
    };

    println!("Received command: {}", command);

    message_hex
}

fn parse_version_and_verack_message(message: [u8; 1024]) -> String {
    let received_magic_bytes = &message[0..4]; // 4 bytes
    let received_command = &message[4..16]; // 12 bytes
    let received_size = &message[16..20]; // 4 bytes
    let received_checksum = &message[20..24]; // 4 bytes

    let mut received_size_copy_fixed = [0u8; 4];

    received_size_copy_fixed.copy_from_slice(&received_size);

    let received_payload_size = u32::from_le_bytes(received_size_copy_fixed);

    let received_payload_end = (received_payload_size + 24) as usize;

    let received_payload = &message[24..received_payload_end];

    println!(
        "Received magic bytes: {}",
        hex::encode(received_magic_bytes)
    );
    println!("Received command: {}", hex::encode(received_command));
    println!("Received size: {}", hex::encode(received_size));
    println!("Received size int: {}", received_payload_size);
    println!("Received checksum: {}", hex::encode(received_checksum));
    println!("Received payload: {}", hex::encode(received_payload));

    let received_verack = &message[received_payload_end..(received_payload_end + 24)]; // 24 bytes

    println!("Received verack: {}", hex::encode(received_verack));

    hex::encode(received_verack)
}

pub fn create_version_message() -> String {
    let mut payload = String::new();

    let protocol_version: u32 = 70014;
    let protocol_version_hex = hex::encode(protocol_version.to_le_bytes());
    payload.push_str(&protocol_version_hex);

    let services: i64 = 0;
    let services_hex = hex::encode(&services.to_le_bytes());
    payload.push_str(&services_hex);

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let unix_timestamp = duration_since_epoch.as_secs();
    let unix_timestamp_hex = hex::encode(unix_timestamp.to_le_bytes());
    payload.push_str(&unix_timestamp_hex);

    let remote_services: i64 = 0;
    let remote_services_hex = hex::encode(&remote_services.to_le_bytes());
    payload.push_str(&remote_services_hex);

    let remote_ip_v6 = NODE_IP.to_ipv6_mapped();
    let remote_ip_hex_concat = remote_ip_v6
        .segments()
        .iter()
        .map(|segment| format!("{:04x}", segment))
        .collect::<Vec<_>>()
        .join("");
    payload.push_str(&remote_ip_hex_concat);

    let remote_port: i16 = 8333;
    let remote_port_hex = hex::encode(remote_port.to_be_bytes());
    payload.push_str(&remote_port_hex);

    let local_services: i64 = 0;
    let local_services_hex = hex::encode(&local_services.to_le_bytes());
    payload.push_str(&local_services_hex);

    let local_ip_v6 = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
    let local_ip_hex_concat = local_ip_v6
        .segments()
        .iter()
        .map(|segment| format!("{:04x}", segment))
        .collect::<Vec<_>>()
        .join("");
    payload.push_str(&local_ip_hex_concat);

    let local_port: u16 = NODE_PORT;
    let local_port_hex = hex::encode(local_port.to_be_bytes());
    payload.push_str(&local_port_hex);

    let nonce: i64 = 0;
    let nonce_hex = hex::encode(&nonce.to_le_bytes());
    payload.push_str(&nonce_hex);

    let user_agent = "welcome";
    let user_agent_hex = hex::encode(&user_agent);
    let user_agent_size: i8 = (user_agent_hex.len() / 2)
        .try_into()
        .expect("User agent len does not fit into i8");
    let user_agent_size_hex = hex::encode(&user_agent_size.to_le_bytes());
    payload.push_str(&user_agent_size_hex);
    payload.push_str(&user_agent_hex);

    let last_block: i32 = 0;
    let last_block_hex = hex::encode(&last_block.to_le_bytes());
    payload.push_str(&last_block_hex);

    let relay_hex = "01";
    payload.push_str(&relay_hex);

    println!("protocol_version_hex: {:?}", protocol_version_hex);
    println!("services_hex: {:?}", services_hex);
    println!("unix_timestamp_hex: {:?}", unix_timestamp_hex);
    println!("remote_services_hex: {:?}", remote_services_hex);
    println!("remote_ip_hex_concat: {:?}", remote_ip_hex_concat);
    println!("remote_port_hex: {:?}", remote_port_hex);
    println!("local_services_hex: {:?}", local_services_hex);
    println!("local_ip_hex_concat: {:?}", local_ip_hex_concat);
    println!("local_port_hex: {:?}", local_port_hex);
    println!("nonce_hex: {:?}", nonce_hex);
    println!("user_agent_size_hex: {:?}", user_agent_size_hex);
    println!("user_agent_hex: {:?}", user_agent_hex);
    println!("last_block_hex: {:?}", last_block_hex);
    println!("relay_hex: {:?}", relay_hex);
    println!("{:?}", payload);

    let mut header = String::new();

    let command = String::from(hex::encode("version")) + "0000000000";

    let payload_len: u32 = (payload.len() as u32) / 2;
    let size = hex::encode(payload_len.to_le_bytes());

    let checksum_hash_full = double_sha256(&payload);
    println!("checksum full: {:?}", checksum_hash_full);
    let checksum = &checksum_hash_full[0..8];

    println!("magic_bytes: {:?}", MAGIC_BYTES);
    println!("command: {:?}", command);
    println!("size: {:?}", size);
    println!("checksum: {:?}", checksum);

    header.push_str(MAGIC_BYTES);
    header.push_str(&command);
    header.push_str(&size);
    header.push_str(&checksum);

    let mut message = String::new();

    message.push_str(&header);
    message.push_str(&payload);

    println!("{}", message);

    message
}
