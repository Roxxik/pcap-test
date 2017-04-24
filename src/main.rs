
extern crate pcap;
extern crate argparse;
extern crate pktparse;
extern crate nom;
extern crate futures;
extern crate core;
extern crate tokio_core;
extern crate libc;

use std::fmt;

use pcap::{Capture, Packet, PacketCodec, Error};
//use argparse::{ ArgumentParser, Store };
//
use pktparse::ipv4::{parse_ipv4_header, IPv4Protocol};
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use nom::IResult;

use futures::{Stream, IntoFuture, Poll, Future};
use futures::future::{ok, FutureResult};
use futures::stream::Fold;

use tokio_core::reactor::Core;
//
//struct Args {
//    filter: String,
//}
//
//fn parse_args() -> Args {
//    let mut args: Args = Args { filter: "".to_string() };
//    {
//        let mut parser = ArgumentParser::new();
//        parser.set_description("hogger a nettop like tool");
//        parser.refer(&mut args.filter).add_option(&["-f"], Store, "bpf filter");
//
//        parser.parse_args_or_exit();
//    }
//    args
//}
//
//fn match_packet(packet: Packet) {
//    let ipv4_packet = &packet[0x10 ..];
//    if let IResult::Done(ipv4_payload, ipv4_header) = parse_ipv4_header(ipv4_packet) {
//        if ipv4_header.protocol == IPv4Protocol::TCP {
//            if let IResult::Done(tcp_payload, tcp_header) = parse_tcp_header(ipv4_payload) {
//                println!("{}:{} -> {}:{}", ipv4_header.source_addr, tcp_header.source_port, ipv4_header.dest_addr, tcp_header.dest_port);
//
//            }
//        }
//    }
//}
//fn cap1() {
//    let args = parse_args();
//
//    let cap = Capture::from_device("any").unwrap();
//    let mut cap = cap.open().unwrap();
//    let _ = cap.filter(&*args.filter);
//
//    let mut packets = 0;
//    let mut bytes = 0;
//
//    while let Ok(packet) = cap.next() {
//        match_packet(packet);
//        packets += 1;
//        //bytes += packet.header.len;
//        //println!("{}, {} ({})", packets, bytes, bytes / packets);
//        if packets == 1000 {
//            break;
//        }
//    }
//    println!("{:?}", cap.stats());
//}

use std::net::Ipv4Addr;

#[derive(Clone)]
struct Connection {
    ip1: Ipv4Addr,
    ip2: Ipv4Addr,
    port1: u16,
    port2: u16,
    packets: u64,
    bytes: u64,
    last_seen: libc::timeval,
}

impl Connection {
    fn new(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, src_port: u16, dst_port: u16, bytes: u64, ts: libc::timeval) -> Connection {
        Connection {
            ip1: src_addr,
            ip2: dst_addr,
            port1: src_port,
            port2: dst_port,
            packets: 1,
            bytes: bytes,
            last_seen: ts,
        }
    }
    fn matches(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> bool {
        let one_way =
            self.ip1 == src_ip
        &&  self.ip2 == dst_ip
        &&  self.port1 == src_port
        &&  self.port2 == dst_port;
        let other_way =
            self.ip2 == src_ip
        &&  self.ip1 == dst_ip
        &&  self.port2 == src_port
        &&  self.port1 == dst_port;
        return one_way || other_way;
    }

    fn update(&mut self, header: &pcap::PacketHeader) {
        self.packets += 1;
        self.bytes += header.len as u64;
        self.last_seen = header.ts;
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(fmt, "{}:{} {}:{} {}({})", self.ip1, self.port1, self.ip2, self.port2, self.bytes, self.packets)
    }
}

#[derive(Clone)]
struct Counter {
    tcp_conn: Vec<Connection>,
    udp_conn: Vec<Connection>,
}

impl Counter {
    fn new() -> Counter {
        Counter { tcp_conn: vec![], udp_conn: vec![] }
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for conn in self.tcp_conn.iter() {
            write!(fmt, "tcp: {}\n", conn)?;
        }
        for conn in self.udp_conn.iter() {
            write!(fmt, "udp: {}\n", conn)?;
        }
        write!(fmt, "\n")
    }
}

enum Protocol {
    TCP,
    UDP,
}
struct CounterCodec{}

impl PacketCodec for CounterCodec {
    type Type = Option<(Protocol, Connection)>;
    fn decode<'a>(&mut self, packet: Packet<'a>) -> Result<Self::Type, Error> {
        use Protocol::*;
        let ipv4_packet = &packet[0x10 ..]; // skipping sll header TODO fix this to support other devices than any
        Ok(if let IResult::Done(ipv4_payload, ipv4_header) = parse_ipv4_header(ipv4_packet) {
            let tmp = match ipv4_header.protocol {
                IPv4Protocol::TCP => {
                    if let IResult::Done(_tcp_payload, tcp_header) = parse_tcp_header(ipv4_payload) {
                        Some((TCP, tcp_header.source_port, tcp_header.dest_port))
                    } else { None }
                },
                IPv4Protocol::UDP => {
                    if let IResult::Done(_udp_payload, udp_header) = parse_udp_header(ipv4_payload) {
                        Some((UDP, udp_header.source_port, udp_header.dest_port))
                    } else { None }
                },
            };
            if let Some((protocol, src_port, dst_port)) = tmp {
                Some((protocol, Connection::new(ipv4_header.source_addr, ipv4_header.dest_addr, src_port, dst_port, packet.header.len as u64, packet.header.ts)))
            } else {
                None
            }
        } else { None })
        //Connection::new(ipv4_header.source_addr, ipv4_header.dest_addr, tcp_header.source_port, tcp_header.dest_port, packet.header.len as u64, packet.header.ts)
        //let ipv4_packet = &packet[0x10 ..]; // skipping sll header TODO fix this to support other devices than any
        //if let IResult::Done(ipv4_payload, ipv4_header) = parse_ipv4_header(ipv4_packet) {
        //    let tmp = match ipv4_header.protocol {
        //        IPv4Protocol::TCP => {
        //            if let IResult::Done(_tcp_payload, tcp_header) = parse_tcp_header(ipv4_payload) {
        //                Some((&mut self.tcp_conn, tcp_header.source_port, tcp_header.dest_port))
        //            } else { None }
        //        },
        //        IPv4Protocol::UDP => {
        //            if let IResult::Done(_udp_payload, udp_header) = parse_udp_header(ipv4_payload) {
        //                Some((&mut self.udp_conn, udp_header.source_port, udp_header.dest_port))
        //            } else { None }
        //        },
        //        _ => None,
        //    };
        //    if let Some((conns, src_port, dst_port)) = tmp {
        //        let mut found = false;
        //        for ref mut conn in conns.iter_mut() {
        //            if conn.matches(ipv4_header.source_addr, ipv4_header.dest_addr, src_port, dst_port) {
        //                conn.update(packet.header);
        //                found = true;
        //            }
        //        }
        //        if !found {
        //            let mut conn_new = Connection {
        //                ip1: ipv4_header.source_addr,
        //                ip2: ipv4_header.dest_addr,
        //                port1: src_port,
        //                port2: dst_port,
        //                packets: 0,
        //                bytes: 0,
        //                last_seen: libc::timeval { tv_sec: 0, tv_usec: 0 }
        //            };
        //            conn_new.update(packet.header);
        //            conns.push(conn_new);
        //        }
        //    }
        //}
        //Ok(self.clone())
    }
}

fn ma1n() -> Result<(),Error> {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let cap = Capture::from_device("any")?.open()?;
    let s = cap.stream(&handle, CounterCodec{})?;
    let done = s.for_each(move |conn| {
        println!("{}", cnt);
        Ok(())
    });
    core.run(done).unwrap();
    Ok(())
}

fn main() {
    match ma1n() {
        Ok(()) => (),
        Err(e) => println!("{:?}", e),
    }
}
