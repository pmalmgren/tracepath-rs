use std::net::UdpSocket;
use std::error::Error;
use clap::{Arg, App};
use nix::cmsg_space;
use nix::sys::uio::IoVec;
use nix::sys::socket::{recvmsg, MsgFlags, ControlMessageOwned};
use nix::sys::select::{FdSet, select};
use nix::sys::time::TimeVal;
use libc;
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::Ipv4Addr;

fn udp_socket() -> UdpSocket {
    UdpSocket::bind("0.0.0.0:0")
        .expect("Failed to bind socket")
}

fn udp_socket_v6() -> UdpSocket {
    UdpSocket::bind("[::/0]:0")
        .expect("Failed to bind socket")
}

unsafe fn set_sockopts(sock: RawFd) -> Result<(), Box<dyn Error>> {
    let mut opt = [1; 1];
    opt[0] = 1;
    let err = libc::setsockopt(sock, libc::SOL_IP, libc::IP_RECVERR, opt.as_ptr() as *mut libc::c_void, 4);

    if err == -1 {
        println!("IP_RECVERR error");
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    let err = libc::setsockopt(sock, libc::SOL_IP, libc::IP_RECVTTL, opt.as_ptr() as *mut libc::c_void, 4);

    if err == -1 {
        println!("IP_RECVTLL error");
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    opt[0] = 2;
    let err = libc::setsockopt(sock, libc::SOL_IP, libc::IP_MTU_DISCOVER, opt.as_ptr() as *mut libc::c_void, 4);

    if err == -1 {
        println!("IP_RETOPS error");
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    Ok(())
}

fn prepare_socket(sock: &UdpSocket, host: &String, ttl: u32) {
    let raw_fd: RawFd = sock.as_raw_fd();
    sock.connect(&host).expect("Error connecting");
    unsafe {
        set_sockopts(raw_fd).unwrap();
    }
    sock.set_ttl(ttl+1)
        .expect(format!("Failed to set ttl={} on socket", ttl).as_str());
}

fn send_datagram(sock: &UdpSocket) {
    let bytes = b"hello\0";
    match sock.send(bytes) {
        Ok(_nbytes) => {},
        Err(_e) => {},
    }
}

struct HopResult {
    addr: Option<String>,
    est_ttl: Option<u8>,
}

impl HopResult {
    fn new() -> Self {
        HopResult { addr: None, est_ttl: None }
    }
}

fn recv_hop_cmsg(sock: &UdpSocket) -> Result<Box<HopResult>, Box<nix::Error>> {
    let raw_fd: RawFd = sock.as_raw_fd();
    let mut data = [0; 65536];
    let iov = IoVec::from_mut_slice(&mut data);
    let mut cmsg = cmsg_space!([RawFd; 28]);
    let mut readset = FdSet::new();
    readset.insert(raw_fd);

    let mut timeout = TimeVal::from(libc::timeval{tv_sec: 1, tv_usec: 0});
    if let Err(e) = select(None, Some(&mut readset), None, None, Some(&mut timeout)) {
        return Err(Box::new(e));
    }

    let mut hop_result = Box::new(HopResult::new());
    let result = recvmsg(raw_fd, &[iov], Some(&mut cmsg), MsgFlags::MSG_ERRQUEUE);

    if let Err(e) = result {
        return Err(Box::new(e));
    }

    let msg = result.unwrap();

    for cmsg in msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::IpTtl(ip_ttl) => {
                hop_result.est_ttl = Some(match ip_ttl {
                    ittl if ittl <= 64 => 64 - ip_ttl,
                    ittl if ittl <= 128 => 128 - ip_ttl,
                    ittl if ittl < 255 => 255 - ip_ttl,
                    _ => 0,
                });
            },
            ControlMessageOwned::IpRecvErr(err) => {
                hop_result.addr = Some(Ipv4Addr::from(err.offender.sin_addr.s_addr.to_be()).to_string());
            },
            _ => {},
        };
    }

    return Ok(hop_result);
}

fn traceroute(hostname: String, hops: u32) {
    let mut trace_complete = false;
    for ttl in 0..hops {
        let port = 33435 + ttl;
        let mut success = false;
        for _retry in 0..3 {
            let sock = udp_socket();
            let host = format!("{}:{}", hostname, port);
            prepare_socket(&sock, &host, ttl);
            send_datagram(&sock);
            let peer = sock.peer_addr().unwrap().to_string();
            let parts: Vec<&str> = peer.split(":").collect();
            assert_eq!(parts.len(), 2);

            match recv_hop_cmsg(&sock) {
                Err(_err) => {
                    success = false;
                    continue;
                },
                Ok(hop_result) => {
                    if let Some(addr) = hop_result.addr {
                        println!("{}: {} (dest: {})", ttl+1, addr, parts[0]);
                        trace_complete = addr == parts[0];
                    } else {
                        println!("{}: no reply", ttl+1);
                    }
                    success = true;
                    break;
                }
            };
        }
        if !success {
            println!("{}: no reply", ttl+1);
        }
        if trace_complete {
            break;
        }
    }
}

fn main() {
    let matches = App::new("traceroute-rs")
        .version("0.1")
        .author("Peter Malmgren <ptmalmgren@gmail.com>")
        .about("Rust version of traceroute")
        .arg(Arg::new("hostname")
            .about("The hostname to run traceroute against")
            .required(true)
            .index(1))
        .arg(Arg::new("hops")
            .short('m')
            .multiple(false)
            .takes_value(true)
            .about("use maximum <hops>"))
        .arg(Arg::new("dns")
            .short('n')
            .multiple(false)
            .takes_value(false)
            .about("no dns name resolution"))
        .get_matches();

    let hostname: String = matches.value_of_t("hostname").unwrap();
    let hops: u32 = matches.value_of_t("hops").unwrap_or(5);
    
    traceroute(hostname, hops);
}
