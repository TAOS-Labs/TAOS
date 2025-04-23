use alloc::{sync::Arc, vec};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};
use spin::Mutex;

use crate::{
    constants::processes::MAX_FILES,
    net::{get_eph_port, with_interface, DeviceInterface},
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
    // The file descriptor given was not a valid file = EBADF
    NotAnOpenFile,
    // The file descriptor given was not a socket = ENOTSOC
    NotASocket,
    // The address was already used, or all ephenepheral ports were used = EADDRINUSE
    AddressInUse,
    // Tried to bind to an already bound value = EINVAL
    SocketAlreadyBound,
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

pub fn sys_bind(socket_fd: u64, sock_addr_ptr: u64, addrlen: u64) -> u64 {
    if bind_impl(socket_fd, sock_addr_ptr, addrlen).is_err() {
        return u64::MAX;
    }
    0
}

pub fn bind_impl(socket_fd: u64, sock_addr_ptr: u64, _addrlen: u64) -> Result<(), SocketError> {
    let socket_size: usize = socket_fd.try_into().unwrap();
    if socket_size > MAX_FILES {
        return Result::Err(SocketError::NotAnOpenFile);
    }
    let file = with_current_pcb(|pcb| pcb.fd_table[socket_size].clone());
    let file = file.ok_or(SocketError::NotAnOpenFile)?;
    if let FakeFile::Socket(socket) = file {
        let socket_guard = socket.lock();
        match socket_guard.clone() {
            Socket::Internet(inet_socket) => {
                bind_internet_socket(inet_socket, sock_addr_ptr)?;
                Ok(())
            }
            Socket::Unix(_domain_socket) => {
                todo!()
            }
        }
    } else {
        Result::Err(SocketError::NotASocket)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct SockAddr {
    sa_family: u32,
    // In NETWORK byte order (big endian)
    port: u16,
    // In NETWORK byte order (big endian)
    sin_addr: u32,
}

fn bind_internet_socket(
    inet_socket: InternetSocket,
    sock_addr_ptr: u64,
) -> Result<(), SocketError> {
    let sock_addr_size: usize = sock_addr_ptr.try_into().unwrap();
    let sock_addr_ptr = sock_addr_size as *const SockAddr;
    let sock_addr = unsafe { *sock_addr_ptr };
    let network_ports = sock_addr.port.to_be();
    let network_addr = sock_addr.sin_addr.to_be_bytes();
    let ipv4_addr = Ipv4Address::new(
        network_addr[0],
        network_addr[1],
        network_addr[2],
        network_addr[3],
    );
    let ip_ep = IpEndpoint {
        addr: IpAddress::Ipv4(ipv4_addr),
        port: network_ports,
    };
    match inet_socket {
        InternetSocket::UDP(udp_socket) => {
            with_interface(|interface| bind_udp_socket(interface, ip_ep, udp_socket))
                .ok_or(SocketError::NoInterface)?
        }
        InternetSocket::TCP(tcp_socket) => {
            with_interface(|interface| bind_tcp_socket(interface, ip_ep, tcp_socket))
                .ok_or(SocketError::NoInterface)?
        }
        InternetSocket::Raw(_raw_socket) => {
            todo!()
        }
    }
}

fn bind_udp_socket(
    interface: &mut DeviceInterface,
    ip_ep: IpEndpoint,
    udp_socket: UDPSocket,
) -> Result<(), SocketError> {
    let udp_socket = interface.sockets.get_mut::<udp::Socket>(udp_socket.handle);
    udp_socket
        .bind(ip_ep)
        .map_err(|_| SocketError::SocketAlreadyBound)?;
    Result::Ok(())
}

fn bind_tcp_socket(
    interface: &mut DeviceInterface,
    ip_ep: IpEndpoint,
    tcp_socket: TCPSocket,
) -> Result<(), SocketError> {
    let tcp_socket = interface.sockets.get_mut::<tcp::Socket>(tcp_socket.handle);
    let local_endpoint = get_eph_port().ok_or(SocketError::AddressInUse)?;
    tcp_socket
        .connect(interface.interface.context(), ip_ep, local_endpoint)
        .map_err(|_| SocketError::SocketAlreadyBound)?;

    Result::Ok(())
}
