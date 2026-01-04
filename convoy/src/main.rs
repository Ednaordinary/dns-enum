extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::interfaces;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags::SYN, TcpOption, TcpPacket},
};
use pnet::transport::{TransportReceiver, TransportSender, ipv4_packet_iter, transport_channel};
use pnet::util::{MacAddr, checksum};
use pnet_macros_support::types::u16be;

use cidr_utils::cidr::Ipv4Cidr;

use std::any::Any;
use std::env;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

mod socket;

fn recv(mut rx: Box<dyn DataLinkReceiver>, mac: Option<MacAddr>) {
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet_vec: Vec<u8>;
                match mac.is_some() {
                    true => {
                        let eth = EthernetPacket::new(packet).unwrap();
                        packet_vec = eth.payload().to_vec();
                    }
                    false => {
                        packet_vec = packet.to_vec();
                    }
                }
                let ip_packet = Ipv4Packet::new(&packet_vec).unwrap();
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet: TcpPacket = TcpPacket::new(&packet_vec).unwrap();
                        println!(
                            "Tcp {0}:{1} -> {2}:{3} - {4}",
                            ip_packet.get_source(),
                            tcp_packet.get_source().to_string(),
                            ip_packet.get_destination().to_string(),
                            tcp_packet.get_destination().to_string(),
                            tcp_packet.get_flags().to_string(),
                        );
                    }
                    packet_type => {
                        println!("Received {} packet", packet_type.to_string());
                    }
                }
            }
            Err(e) => {
                println!("Error while receiving packet: {}", e)
            }
        }
    }
}

fn craft_ip_packet<'a>(source_ip: Ipv4Addr, buffer: &'a mut [u8]) -> MutableIpv4Packet<'a> {
    let mut ip_packet = MutableIpv4Packet::new(buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_source(source_ip);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet
}

// Copied from pnet::utils
fn ipv4_word_sum(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

// Copied from pnet::utils
fn finalize_checksum(mut sum: u32) -> u16be {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

// Copied from pnet::utils
fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    if data.len() == 0 {
        return 0;
    }
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != skipword {
            // It's safe to unwrap because we verified there are at least 2 bytes
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    // If the length is odd, make sure to checksum the final byte
    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

fn send_packets(
    source_ip: &Ipv4Addr,
    remote_ips: &Vec<Ipv4Cidr>,
    source_port: u16,
    remote_ports: Vec<u16>,
    mut tx: socket::RawSocket,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packets = 0u64;
    let mut packets_size = 0u64;
    for remote_port in remote_ports {
        for ip_set in remote_ips {
            let mut ip_buffer = [0; 40];
            let tcp_seq = rand::random::<u32>();
            let mut ip_packet = craft_ip_packet(*source_ip, &mut ip_buffer);
            //let mut base_packet = craft_base_packet(source_port, remote_port, ip_packet.payload_mut(), tcp_seq)?;
            {
                let mut base_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
                base_packet.set_source(source_port);
                base_packet.set_destination(remote_port);
                base_packet.set_sequence(tcp_seq);
                base_packet.set_window(64240);
                base_packet.set_data_offset(8);
                base_packet.set_flags(SYN);
                base_packet.set_data_offset(5);
            }
            let mut packet = MutableIpv4Packet::from(ip_packet);
            let mut unfinished_sum = 0u32;
            let mut dyn_sum: u32;
            unfinished_sum += ipv4_word_sum(source_ip);
            let protocol = IpNextHeaderProtocols::Tcp;
            let IpNextHeaderProtocol(protocol) = protocol;
            unfinished_sum += protocol as u32;
            unfinished_sum += 20; // data.len()
            for ip in ip_set.iter().addresses() {
                //let mut packet = MutableIpv4Packet::from(ip_packet);
                packet.set_destination(ip);
                //let mut packet = craft_dest_packet(&ip, &mut buffer, &base_packet, unfinished_sum);
                let immut_ip = packet.to_immutable();
                packet.set_checksum(checksum(immut_ip.packet(), 5));
                let mut base_packet = MutableTcpPacket::new(packet.payload_mut()).unwrap();
                dyn_sum = unfinished_sum;
                dyn_sum += ipv4_word_sum(&ip);
                dyn_sum += sum_be_words(base_packet.packet(), 8);
                base_packet.set_checksum(finalize_checksum(dyn_sum));

                //println!("sending packet");
                //println!("{:02x?}", packet.packet());
                //println!("{}", ip);
                packets += 1;
                packets_size += packet.packet().len() as u64;
                //tx.send_to(&packet, std::net::IpAddr::V4(ip)).unwrap();
                //tx.send_blocking(&packet.packet());
            }
        }
    }
    println!("Packets: {}", packets);
    println!("Total bytes: {}", packets_size);
    Ok(())
}

fn calculate_ips(ranges: Vec<String>) -> Vec<Ipv4Cidr> {
    let ips: Vec<Ipv4Cidr> = ranges
        .into_iter()
        .map(|x| Ipv4Cidr::from_str(&x).expect(&format!("Could not parse {}", x)))
        .collect();
    ips
}

fn craft_transport(
    interface: &NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let mut config = datalink::Config::default();
    config.read_timeout = Some(Duration::from_secs(1));
    match datalink::channel(interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Bad channel type"),
        Err(e) => panic!("Error: {}", e),
    }
}

fn main() {
    let range = env::args().nth(1).unwrap();
    let mut ranges: Vec<String> = Vec::new();
    ranges.push(range);
    let ips = calculate_ips(ranges);
    let mut ports: Vec<u16> = Vec::new();
    (20..21).for_each(|x| ports.push(x));
    let ifs = interfaces();
    let interface = ifs
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .unwrap();
    let (_, rx) = craft_transport(interface);
    let mac: Option<MacAddr> = interface.mac;
    std::thread::spawn(move || {
        recv(rx, mac);
    });
    let tx = socket::RawSocket::new(&interface.name).unwrap();
    let ip = interface.ips.first().unwrap().ip();
    println!("if: {}", interface.name);
    // let ip: IpAddr = IpAddr::from(Ipv4Addr::new(0, 0, 0, 0));
    match ip {
        IpAddr::V4(v4_addr) => {
            println!("{}", v4_addr);
            let _ = send_packets(&v4_addr, &ips, 23456, ports, tx);
        }
        IpAddr::V6(v6_addr) => {
            println!("Source is v6!");
        }
    }
    std::thread::sleep(Duration::from_secs(1));
}
