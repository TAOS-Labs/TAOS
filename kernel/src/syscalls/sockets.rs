#[repr(u32)]
#[allow(dead_code)]
enum SocketDomains {
    Unspecified = 0,
    // Unix domain sockets for local communication
    Unix = 1,
    // IP protocol sockets
    Inet = 2,
}

#[repr(u32)]
#[allow(dead_code)]
enum InetSocketTypes {
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
pub struct UDPSocket {}

#[derive(Debug, Clone)]
pub struct TCPSocket {}

#[derive(Debug, Clone)]
pub struct RawSocket {}
