use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::net::{SocketAddr, TcpStream};

mod messages;
mod utils;

use messages::{create_version_message, parse_received_message};

const NODE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 12);
const NODE_PORT: u16 = 8333;

fn main() {
    let socket_addr = SocketAddr::new(NODE_IP.into(), NODE_PORT);
    let mut stream = TcpStream::connect(socket_addr).expect("Failed to connect to BTC node.");

    let version_message = create_version_message();

    let write_result = stream.write_all(&hex::decode(version_message).expect("Failed to decode"));
    stream.flush().expect("Error flushing data.");

    println!("write_result: {:?}", write_result);

    let mut buf = [0u8; 1024];

    let bytes_read = stream.read(&mut buf).expect("Err reading from stream");

    let received_verack = parse_received_message(buf, bytes_read);

    let write_result = stream.write_all(&hex::decode(&received_verack).expect("Failed to decode"));
    stream.flush().expect("Error flushing data.");

    println!("write_result: {:?}", write_result);

    loop {
        let mut buf = [0u8; 1024];

        let bytes_read = stream.read(&mut buf).expect("Err reading from stream");

        parse_received_message(buf, bytes_read);
    }
}
