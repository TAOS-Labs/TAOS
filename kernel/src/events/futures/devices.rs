use alloc::sync::Arc;
use core::{
    fmt::LowerHex,
    future::Future,
    ops::BitAnd,
    pin::Pin,
    ptr::read_volatile,
    task::{Context, Poll},
};

use futures::task::ArcWake;

use crate::{
    devices::sd_card::{PresentState, SDCardError},
    events::{current_running_event, runner_timestamp, Event},
};

/// Future to sleep an event until a target timestamp (in system ticks)
#[derive(Clone)]
pub struct SDCardReq {
    target_state: PresentState,
    present_state_register_addr: *const u32,
    timeout_timestamp: u64,
    event: Arc<Event>,
}

unsafe impl Send for SDCardReq {}

impl SDCardReq {
    pub fn new(
        target_state: PresentState,
        present_state_register_addr: *const u32,
        timeout_timestamp: u64,
        event: Arc<Event>,
    ) -> SDCardReq {
        SDCardReq {
            present_state_register_addr,
            target_state,
            timeout_timestamp,
            event,
        }
    }

    pub fn awake(&self) {
        self.event.clone().wake();
    }

    pub fn get_id(&self) -> u64 {
        self.event.eid.0
    }
}

/// Order SDCardReq futures with earlier timestamps given "higher" values.
///
/// PID then EID to tie break.
/// Thus, events created earlier awaken first in the very rare event of a tie.
/// This helps preventing compounding error from old events frequently blocking.
impl Ord for SDCardReq {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timeout_timestamp
            .cmp(&other.timeout_timestamp)
            .reverse()
            .then(self.event.pid.cmp(&other.event.pid))
            .then(self.event.eid.cmp(&other.event.eid))
    }
}

impl PartialOrd for SDCardReq {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SDCardReq {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_timestamp == other.timeout_timestamp
            && self.event.pid == other.event.pid
            && self.event.eid == other.event.eid
    }
}

impl Eq for SDCardReq {}

impl Future for SDCardReq {
    type Output = Result<(), SDCardError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let system_time = runner_timestamp();

        if self.timeout_timestamp <= system_time {
            return Poll::Ready(Result::Err(SDCardError::SDTimeout));
        }

        let present_state = unsafe {
            PresentState::from_bits_retain(core::ptr::read_volatile(
                self.present_state_register_addr,
            ))
        };

        if self.target_state.intersects(present_state) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone)]
pub struct HWRegisterWrite<T: BitAnd<Output = T> + PartialEq + Copy> {
    reg: *mut T,
    mask: T,
    expected: T,
    event: Arc<Event>,
}

unsafe impl<T: BitAnd<Output = T> + PartialEq + Copy> Send for HWRegisterWrite<T> {}

impl<T: BitAnd<Output = T> + PartialEq + Copy> HWRegisterWrite<T> {
    pub fn new(reg: *mut T, mask: T, expected: T) -> HWRegisterWrite<T> {
        HWRegisterWrite {
            reg,
            mask,
            expected,
            event: current_running_event().expect("Blocking on MMIO HW Register outside event"),
        }
    }

    pub fn awake(&self) {
        self.event.clone().wake();
    }

    pub fn get_id(&self) -> u64 {
        self.event.eid.0
    }
}

/// Order SDCardReq futures with earlier timestamps given "higher" values.
///
/// PID then EID to tie break.
/// Thus, events created earlier awaken first in the very rare event of a tie.
/// This helps preventing compounding error from old events frequently blocking.
impl<T: BitAnd<Output = T> + PartialEq + Copy> Ord for HWRegisterWrite<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.event.eid.cmp(&other.event.eid)
    }
}

impl<T: BitAnd<Output = T> + PartialEq + Copy> PartialOrd for HWRegisterWrite<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: BitAnd<Output = T> + PartialEq + Copy> PartialEq for HWRegisterWrite<T> {
    fn eq(&self, other: &Self) -> bool {
        self.event.eid == other.event.eid
    }
}

impl<T: BitAnd<Output = T> + PartialEq + Copy> Eq for HWRegisterWrite<T> {}

impl<T: BitAnd<Output = T> + PartialEq + Copy + LowerHex> Future for HWRegisterWrite<T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            if (read_volatile(self.reg) & self.mask) == self.expected {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
}
