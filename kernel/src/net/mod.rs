use core::sync::atomic::{AtomicBool, AtomicU16};

use alloc::{collections::btree_set::BTreeSet, sync::Arc, vec};
use lazy_static::lazy_static;
use smoltcp::{
    iface::{Interface, SocketHandle, SocketSet},
    socket::dhcpv4,
    time::Instant,
    wire::{EthernetAddress, IpCidr, Ipv4Cidr},
};
use spin::{Mutex, RwLock};

use crate::{debug, debug_println, devices::xhci::ecm::ECMDevice};
const EPHEMERAL_PORTS_START: u16 = 49152;
static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(EPHEMERAL_PORTS_START);
static EPHEMERAL_PORTS_OVERFLOW: AtomicBool = AtomicBool::new(false);
pub static INTERFACE: Mutex<Option<DeviceInterface>> = Mutex::new(Option::None);

lazy_static! {
    pub static ref PORTS_SET: Arc<RwLock<BTreeSet<u16>>> = Arc::new(RwLock::new(BTreeSet::new()));
}

#[derive(Debug)]
pub enum NetError {
    NoInterface,
    DeviceError,
    NoPackets,
    // We lost our DHCP Lease, so you might want to call get_ip_addr again
    Deconfigured,
}

pub struct DeviceInterface {
    device: ECMDevice,
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    dhcp_handle: Option<SocketHandle>,
}

pub fn set_interface(mut device: ECMDevice, hardware_address: EthernetAddress) {
    let config =
        smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(hardware_address));
    let interface = smoltcp::iface::Interface::new(config, &mut device, Instant::ZERO);
    // Can use 'static because we are using owned buffers for sockets
    // see https://docs.rs/smoltcp/latest/smoltcp/iface/struct.SocketSet.html
    let sockets: SocketSet<'static> = SocketSet::new(vec![]);
    let new_interface = DeviceInterface {
        device,
        interface,
        sockets,
        dhcp_handle: Option::None,
    };

    let mut old_interface = INTERFACE.lock();
    *old_interface = Option::Some(new_interface);
}

/// Get a reference to the global network interface
pub fn get() -> Option<spin::MutexGuard<'static, Option<DeviceInterface>>> {
    let guard = INTERFACE.lock();
    if guard.is_some() {
        Some(guard)
    } else {
        None
    }
}

pub fn with_interface<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut DeviceInterface) -> R,
{
    let mut guard = get()?;
    let interface = guard.as_mut()?;
    Some(f(interface))
}

/// Sends a dhcp request for an ip address.
pub fn get_ip_addr() -> Result<(), NetError> {
    let mut interface = INTERFACE.lock();
    let device_interface = interface.as_mut().ok_or(NetError::NoInterface)?;
    if device_interface.dhcp_handle.is_none() {
        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = device_interface.sockets.add(dhcp_socket);
        device_interface.dhcp_handle = Option::Some(dhcp_handle);
    }

    let packets_sent = device_interface.interface.poll(
        Instant::from_micros(1),
        &mut device_interface.device,
        &mut device_interface.sockets,
    );
    if !packets_sent {
        return Result::Err(NetError::NoPackets);
    }
    let event = device_interface
        .sockets
        .get_mut::<dhcpv4::Socket>(device_interface.dhcp_handle.unwrap())
        .poll();
    match event {
        None => {
            return Result::Err(NetError::NoPackets);
        }
        Some(dhcpv4::Event::Configured(config)) => {
            debug!("DHCP config acquired!");

            debug!("IP address:      {}", config.address);
            set_ipv4_addr(&mut device_interface.interface, config.address);

            if let Some(router) = config.router {
                debug!("Default gateway: {}", router);
                device_interface
                    .interface
                    .routes_mut()
                    .add_default_ipv4_route(router)
                    .unwrap();
            } else {
                debug!("Default gateway: None");
                device_interface
                    .interface
                    .routes_mut()
                    .remove_default_ipv4_route();
            }

            for (i, s) in config.dns_servers.iter().enumerate() {
                debug_println!("DNS server {}:    {}", i, s);
            }
        }
        Some(dhcpv4::Event::Deconfigured) => {
            debug_println!("DHCP lost config!");
            device_interface
                .interface
                .update_ip_addrs(|addrs| addrs.clear());
            device_interface
                .interface
                .routes_mut()
                .remove_default_ipv4_route();
            return Result::Err(NetError::Deconfigured);
        }
    };

    Result::Ok(())
}

fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        addrs.push(IpCidr::Ipv4(cidr)).unwrap();
    });
}

pub fn get_eph_port() -> Option<u16> {
    if EPHEMERAL_PORTS_OVERFLOW.load(core::sync::atomic::Ordering::SeqCst) {
        return Option::None;
    }
    let potential_result = NEXT_EPHEMERAL_PORT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if potential_result < EPHEMERAL_PORTS_START {
        EPHEMERAL_PORTS_OVERFLOW.store(true, core::sync::atomic::Ordering::SeqCst);
        return Option::None;
    }
    Option::Some(potential_result)
}
