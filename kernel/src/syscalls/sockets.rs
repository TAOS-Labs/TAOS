use alloc::{sync::Arc, vec};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
};
use spin::Mutex;

use crate::{
    net::with_interface,
    processes::process::{with_current_pcb, FakeFile},
};

#[repr(u32)]
#[derive(FromPrimitive)]
enum SocketDomain {
    Unspecified = 0,
    // Unix domain sockets for local communication
    Unix = 1,
    // IP protocol sockets
    Inet = 2,
}

#[repr(u32)]
#[derive(FromPrimitive)]
enum InetSocketType {
    /// TCP
    Stream = 1,
    /// UDP
    Datagram = 2,
    /// Raw
    Raw = 3,
}

#[derive(Debug, Clone)]
pub enum Socket {
    Unix(UnixSocket),
    Internet(InternetSocket),
}

/// A socket File Descriptor for IPC
#[derive(Debug, Clone)]
pub struct UnixSocket {}

#[derive(Debug, Clone)]
/// A socket File Descriptor for connecting out to the wider internet
pub enum InternetSocket {
    UDP(UDPSocket),
    TCP(TCPSocket),
    Raw(RawSocket),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UDPSocket {
    handle: SocketHandle,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TCPSocket {
    handle: SocketHandle,
}

#[derive(Debug, Clone)]
pub struct RawSocket {}

pub enum SocketError {
    // Should set errno = EINVAL
    UnsupportedProtocol,
    // Should set errno = EINVAL
    UnsupportedFlags,
    // Should set errno = EMFILE
    NoFreeFileDescriptor,
    // No interface is set up, set errno = ENODEV (but ENXIO also works)
    NoInterface,
}

/// Implementation of the socket system call.
/// Wraps everything up into a u64 (but keep in mind that failures will return
/// usize::MAX ) which should have a equvilent equivilent to -1i64.
/// If kernel code wants to use sockets, they should use socket_impl
/// which has a much more sane error reporting syntax
pub fn sys_socket(domain: u64, socket_type: u64, protocol: u64) -> u64 {
    let stuff = socket_impl(domain, socket_type, protocol).unwrap_or(usize::MAX);
    let return_64: u64 = stuff.try_into().unwrap();
    return_64
}

/// Implementation of the socket system call. Returns the sockets file descriptor
/// or SocketError if the call failed. Invalid arguments will NOT raise
/// assertion errors as this is designed to be called by users
pub fn socket_impl(domain: u64, socket_type: u64, protocol: u64) -> Result<usize, SocketError> {
    let checked_domain = SocketDomain::from_u64(domain).ok_or(SocketError::UnsupportedProtocol)?;

    // Claim a file descriptor
    let fd = with_current_pcb(|pcb| pcb.find_next_fd()).ok_or(SocketError::NoFreeFileDescriptor)?;

    // Send off to the apppropate domain
    match checked_domain {
        SocketDomain::Inet => create_internet_socket(socket_type, protocol, fd),
        SocketDomain::Unix => {
            todo!()
        }
        SocketDomain::Unspecified => Err(SocketError::UnsupportedProtocol),
    }
}

fn create_internet_socket(
    socket_type: u64,
    _protocol: u64,
    fd: usize,
) -> Result<usize, SocketError> {
    let checked_type =
        InetSocketType::from_u64(socket_type).ok_or(SocketError::UnsupportedProtocol)?;
    let internet_socket = match checked_type {
        InetSocketType::Datagram => {
            let rx_buffer = udp::PacketBuffer::new(vec![], vec![0; 4096]);
            let tx_buffer = udp::PacketBuffer::new(vec![], vec![0; 4096]);

            let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);
            let socket_handle = with_interface(|interface| interface.sockets.add(udp_socket))
                .ok_or(SocketError::NoInterface)?;
            let udp_socket = UDPSocket {
                handle: socket_handle,
            };
            InternetSocket::UDP(udp_socket)
        }
        InetSocketType::Raw => {
            todo!();
        }
        InetSocketType::Stream => {
            let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
            let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
            let tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
            let socket_handle = with_interface(|interface| interface.sockets.add(tcp_socket))
                .ok_or(SocketError::NoInterface)?;
            let tcp_socket = TCPSocket {
                handle: socket_handle,
            };
            InternetSocket::TCP(tcp_socket)
        }
    };
    with_current_pcb(|pcb| {
        pcb.fd_table[fd] = Option::Some(FakeFile::Socket(Arc::new(Mutex::new(Socket::Internet(
            internet_socket,
        )))))
    });
    Result::Ok(fd)
}
