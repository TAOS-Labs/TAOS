//! x2APIC (Advanced Programmable Interrupt Controller) management.
//!
//! - Allows for x2APIC initialization for both BSP and AP cores
//! - Provides timer configuration and calibration using PIT
//! - Delivers inter-processor interrupt (IPI) support
//! - Timer masking/unmasking
//! - End-of-interrupt (EOI) handling

use crate::{
    constants::{idt::TIMER_VECTOR, x2apic::CPU_FREQUENCY, MAX_CORES}, interrupts::gdt, serial_println, syscalls::syscall_handlers::syscall_handler_64_naked
};
use core::sync::atomic::{AtomicU32, Ordering};
use raw_cpuid::CpuId;
use spin::Mutex;
use x86_64::{instructions::port::Port, registers::model_specific::{GsBase, KernelGsBase, Msr}, VirtAddr};

use super::gdt::TSSS;

// MSR register constants
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const X2APIC_EOI: u32 = 0x80B;
const X2APIC_SIVR: u32 = 0x80F;
const X2APIC_TPR: u32 = 0x808;
const X2APIC_ID: u32 = 0x802;
const X2APIC_ICR: u32 = 0x830;
const X2APIC_LVT_TIMER: u32 = 0x832;
const X2APIC_TIMER_ICR: u32 = 0x838;
const X2APIC_TIMER_CCR: u32 = 0x839;
const X2APIC_TIMER_DCR: u32 = 0x83E;
const X2APIC_IA32_EFER: u32 = 0xC000_0080;
const X2APIC_IA32_LSTAR: u32 = 0xC000_0082;
const X2APIC_IA32_FMASK: u32 = 0xC000_0084;
const X2APIC_IA32_STAR: u32 = 0xC000_0081;
const X2APIC_IA32_GSBASE: u32 = 0xC000_0101;
const X2APIC_IA32_KERNEL_GSBASE: u32 = 0xC000_0102;
const X2APIC_IA32_SYSENTER_CS: u32 = 0x174;
const X2APIC_IA32_SYSENTER_ESP: u32 = 0x175;
const X2APIC_IA32_SYSENTER_EIP: u32 = 0x176;

/// Programmable Interval Timer (PIT) constants for timer calibration
const PIT_FREQUENCY: u64 = 1_193_182;
const CHANNEL_2_PORT: u16 = 0x42;
const COMMAND_PORT: u16 = 0x43;
const CONTROL_PORT: u16 = 0x61;

#[derive(Debug)]
pub enum X2ApicError {
    /// x2APIC feature not supported by CPU
    NotSupported,
    /// x2APIC not enabled in hardware
    NotEnabled,
    /// Failed to enable x2APIC
    EnableFailed,
    /// Invalid interrupt vector number
    InvalidVector,
    /// General configuration failure
    ConfigurationFailed,
    /// Timer-related error
    TimerError,
    /// Core ID exceeds MAX_CORES
    CoreOutOfRange,
}

/// Errors that can occur during PIT operations
#[derive(Debug)]
pub enum PitError {
    /// Invalid timer duration specified
    InvalidDuration,
    /// Timer calibration failed
    CalibrationFailed,
}

/// Global manager for all x2APICs in the system
static mut APIC_MANAGER: X2ApicManager = X2ApicManager::new();
/// Stores calibrated timer count value shared between cores
static CALIBRATED_TIMER_COUNT: AtomicU32 = AtomicU32::new(0);
/// Global to manage what addresses to invalidate when shootdowns happen
pub static TLB_SHOOTDOWN_ADDR: Mutex<[u64; MAX_CORES]> = Mutex::new([0; MAX_CORES]);

/// Manages x2APIC instances for all CPU cores
pub struct X2ApicManager {
    apics: [Option<X2Apic>; MAX_CORES],
}

impl Default for X2ApicManager {
    fn default() -> Self {
        Self::new()
    }
}

impl X2ApicManager {
    /// Creates a new x2APIC manager with empty APIC slots
    pub const fn new() -> Self {
        const NONE_APIC: Option<X2Apic> = None;
        Self {
            apics: [NONE_APIC; MAX_CORES],
        }
    }

    /// Gets the current CPU core's ID from the x2APIC ID register
    #[inline(always)]
    pub fn current_core_id() -> usize {
        // TODO: Change this to not use MSRs
        // Look into storing in CPU specific registers like gs
        unsafe { Msr::new(X2APIC_ID).read() as usize }
    }

    /// Initializes the x2APIC for the current CPU core
    pub fn initialize_current_core() -> Result<(), X2ApicError> {
        let mut apic = X2Apic::new()?;
        apic.enable()?;
        let id = Self::current_core_id();

        if id >= MAX_CORES {
            return Err(X2ApicError::CoreOutOfRange);
        }

        unsafe {
            APIC_MANAGER.apics[id] = Some(apic);
        }

        Ok(())
    }

    /// Calibrates the APIC timer using the PIT as a reference
    ///
    /// # Arguments
    /// * `hz` - Desired timer frequency in Hertz
    ///
    /// # Returns
    /// Timer count value needed to achieve the requested frequency
    pub fn calibrate_timer(hz: u32) -> Result<u32, X2ApicError> {
        let mut pit = Pit::new();
        pit.calibrate_apic_timer(hz)
            .map_err(|_| X2ApicError::TimerError)
    }

    /// Configures the timer for the current CPU core
    ///
    /// # Arguments
    /// * `counter` - Timer count value from calibration
    #[inline(always)]
    pub fn configure_timer_current_core(counter: u32) -> Result<(), X2ApicError> {
        // Configure timer: Periodic mode (1 << 17), unmasked (0 << 16), vector 32
        let timer_config = (1u64 << 17) | (TIMER_VECTOR as u64);
        unsafe {
            Msr::new(X2APIC_LVT_TIMER).write(timer_config);
            Msr::new(X2APIC_TIMER_DCR).write(0xB); // Set divider to 1
            Msr::new(X2APIC_TIMER_ICR).write(counter as u64);
        }
        Ok(())
    }

    /// Configures the syscall for the current CPU core
    #[inline(always)]
    pub fn configure_syscall_current_core() -> Result<(), X2ApicError> {
        let fmask: u64 = 0x200;
        let user_cs = gdt::GDT.1.user_code_selector.0 as u64;
        let kernel_cs = gdt::GDT.1.code_selector.0 as u64;
        let star: u64 = user_cs << 48 | kernel_cs << 32;

        let sys_addr = syscall_handler_64_naked as usize;
        let core = current_core_id();

        // let stack = ((TSSS[core].privilege_stack_table[0]).as_u64()) & !15;
        // KernelGsBase::write(VirtAddr::new(stack));

        // Set up MSRs for syscall
        unsafe {
            Msr::new(X2APIC_IA32_EFER).write(Msr::new(X2APIC_IA32_EFER).read() | 1);
            Msr::new(X2APIC_IA32_LSTAR).write(sys_addr.try_into().unwrap());
            Msr::new(X2APIC_IA32_FMASK).write(fmask);
            Msr::new(X2APIC_IA32_STAR).write(star);
            Msr::new(X2APIC_IA32_KERNEL_GSBASE).write(KernelGsBase::read().as_u64());

            // Msr::new(X2APIC_IA32_SYSENTER_CS).write(kernel_cs);
            // Msr::new(X2APIC_IA32_SYSENTER_ESP).write(stack);
            // Msr::new(X2APIC_IA32_SYSENTER_EIP).write(sys_addr.try_into().unwrap());
        }

        Ok(())
    }

    /// Sends EOI signal to acknowledge the current interrupt
    #[inline(always)]
    pub fn send_eoi() -> Result<(), X2ApicError> {
        unsafe {
            Msr::new(X2APIC_EOI).write(0);
        }
        Ok(())
    }

    /// Masks the APIC timer
    #[inline(always)]
    pub fn mask_timer() -> Result<(), X2ApicError> {
        unsafe {
            let val = Msr::new(X2APIC_LVT_TIMER).read();
            Msr::new(X2APIC_LVT_TIMER).write(val | (1 << 16));
        }
        Ok(())
    }

    /// Unmasks the APIC timer
    #[inline(always)]
    pub fn unmask_timer() -> Result<(), X2ApicError> {
        unsafe {
            let val = Msr::new(X2APIC_LVT_TIMER).read();
            Msr::new(X2APIC_LVT_TIMER).write(val & !(1 << 16));
        }
        Ok(())
    }

    /// Sends an Inter-Processor Interrupt (IPI) to a specific core
    ///
    /// # Arguments
    /// * `target_id` - ID of the target CPU core
    /// * `vector` - Interrupt vector number (must be >= 16)
    #[inline(always)]
    pub fn send_ipi(target_id: u32, vector: u8) -> Result<(), X2ApicError> {
        if vector < 16 {
            return Err(X2ApicError::InvalidVector);
        }

        let value = ((target_id as u64) << 32) | vector as u64;
        unsafe {
            Msr::new(X2APIC_ICR).write(value);
        }
        Ok(())
    }

    /// Initializes x2APIC for the Bootstrap Processor (BSP)
    ///
    /// # Arguments
    /// * `hz` - Desired timer frequency in Hertz
    pub fn bsp_init(hz: u32) -> Result<(), X2ApicError> {
        // First calibrate the timer
        let count = Self::calibrate_timer(hz)?;
        CALIBRATED_TIMER_COUNT.store(count, Ordering::Release);

        // Then initialize BSP's local APIC
        Self::initialize_current_core()?;
        Self::configure_timer_current_core(count)?;
        Self::configure_syscall_current_core()?;

        Ok(())
    }

    /// Initializes x2APIC for an Application Processor (AP)
    pub fn ap_init() -> Result<(), X2ApicError> {
        let count = CALIBRATED_TIMER_COUNT.load(Ordering::Acquire);
        Self::initialize_current_core()?;
        Self::configure_timer_current_core(count)?;
        Self::configure_syscall_current_core()?;

        Ok(())
    }
}

/// Represents a single x2APIC instance
pub struct X2Apic {
    enabled: bool,
}

impl X2Apic {
    /// Creates a new x2APIC instance if supported by the CPU
    fn new() -> Result<Self, X2ApicError> {
        let cpuid = CpuId::new();
        if !cpuid.get_feature_info().is_some_and(|f| f.has_x2apic()) {
            return Err(X2ApicError::NotSupported);
        }
        Ok(Self { enabled: false })
    }

    /// Enables the x2APIC in hardware and performs basic initialization
    fn enable(&mut self) -> Result<(), X2ApicError> {
        if self.enabled {
            return Ok(());
        }

        unsafe {
            let value = Msr::new(IA32_APIC_BASE_MSR).read();
            Msr::new(IA32_APIC_BASE_MSR).write(value | (1 << 11) | (1 << 10));

            let new_value = Msr::new(IA32_APIC_BASE_MSR).read();
            if (new_value & ((1 << 11) | (1 << 10))) != ((1 << 11) | (1 << 10)) {
                return Err(X2ApicError::EnableFailed);
            }

            // Initialize with default config
            Msr::new(X2APIC_SIVR).write(0xFF | (1 << 8));
            Msr::new(X2APIC_TPR).write(0);
        }

        self.enabled = true;
        Ok(())
    }
}

/// Programmable Interval Timer used for APIC timer calibration
pub struct Pit {
    channel_2: Port<u8>,
    command: Port<u8>,
    control: Port<u8>,
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit {
    /// Creates a new PIT instance with configured I/O ports
    pub fn new() -> Self {
        Self {
            channel_2: Port::new(CHANNEL_2_PORT),
            command: Port::new(COMMAND_PORT),
            control: Port::new(CONTROL_PORT),
        }
    }

    /// Calibrates the APIC timer using PIT as a reference clock
    ///
    /// # Arguments
    /// * `hz` - Desired APIC timer frequency in Hertz
    ///
    /// # Returns
    /// Timer count value needed to achieve the requested frequency
    pub fn calibrate_apic_timer(&mut self, hz: u32) -> Result<u32, PitError> {
        unsafe {
            X2ApicManager::mask_timer().map_err(|_| PitError::CalibrationFailed)?;

            // Set divider to 1
            Msr::new(X2APIC_TIMER_DCR).write(0xB);

            let initial = u32::MAX;
            Msr::new(X2APIC_TIMER_ICR).write(initial as u64);

            // Start PIT measurement
            self.control.write(1);
            self.command.write(0b10110110);

            let pit_divider = PIT_FREQUENCY as u32 / 20;
            if pit_divider > 0xFFFF {
                return Err(PitError::InvalidDuration);
            }

            self.channel_2.write((pit_divider & 0xFF) as u8);
            self.channel_2.write((pit_divider >> 8) as u8);

            let mut last = self.control.read() & 0x20;
            let mut changes = 0;

            while changes < 40 {
                let t = self.control.read() & 0x20;
                if t != last {
                    changes += 1;
                    last = t;
                }
            }

            self.control.write(0);

            // Calculate ticks
            let final_count = Msr::new(X2APIC_TIMER_CCR).read() as u32;
            let diff = initial - final_count;
            Ok(diff / hz)
        }
    }
}

/// Initialize x2APIC for the Bootstrap Processor (BSP)
pub fn init_bsp(hz: u32) -> Result<(), X2ApicError> {
    X2ApicManager::bsp_init(hz)
}

/// Initialize x2APIC for an Application Processor (AP)
pub fn init_ap() -> Result<(), X2ApicError> {
    X2ApicManager::ap_init()
}

/// Send EOI signal to acknowledge the current interrupt
#[inline(always)]
pub fn send_eoi() {
    X2ApicManager::send_eoi().expect("Failed sending interrupt");
}

/// Get the ID of the current CPU core
#[inline(always)]
pub fn current_core_id() -> usize {
    X2ApicManager::current_core_id()
}

/// Send IPI to a specific core
#[inline(always)]
pub fn send_ipi(target_id: u32, vector: u8) {
    X2ApicManager::send_ipi(target_id, vector).expect("Failed sending IPI");
}

/// Mask the APIC timer
#[inline(always)]
pub fn mask_timer() {
    X2ApicManager::mask_timer().expect("Failed to mask timer");
}

/// Unmask the APIC timer
#[inline(always)]
pub fn unmask_timer() {
    X2ApicManager::unmask_timer().expect("Failed to unmask timer");
}

#[inline(always)]
pub fn nanos_to_ticks(nanos: u64) -> u64 {
    (nanos * CPU_FREQUENCY as u64) / 1_000_000_000
}
