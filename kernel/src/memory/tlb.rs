//! Translation Lookaside Buffer Shootdowns
//!
//! - Exposes a function to perform TLB Shootdowns

use crate::{
    constants::{idt::TLB_SHOOTDOWN_VECTOR, MAX_CORES},
    interrupts::x2apic::{current_core_id, send_ipi, TLB_SHOOTDOWN_ADDR},
};
use core::arch::asm;
use x86_64::VirtAddr;

/// Sends an inter-process interrupt to all other cores to clear TLB entry with a specific VA
///
/// # Arguments:
/// * target_vaddr: VA that has to be flushed in all TLBs
pub fn tlb_shootdown(target_vaddr: VirtAddr) {
    let current_core = current_core_id();
    let vaddr = target_vaddr.as_u64();

    {
        // Acquire the lock and update all cores except the current one.
        let mut addresses = TLB_SHOOTDOWN_ADDR.lock();
        for core in 0..MAX_CORES {
            if core != current_core {
                addresses[core] = vaddr;
                send_ipi(core as u32, TLB_SHOOTDOWN_VECTOR);
            }
        }
    }

    unsafe {
        asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags));
    }
}
