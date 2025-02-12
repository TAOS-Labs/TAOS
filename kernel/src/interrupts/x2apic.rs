use crate::constants::idt::TIMER_VECTOR;
use crate::constants::MAX_CORES;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_cpuid::CpuId;
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

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

// PIT constants
const PIT_FREQUENCY: u64 = 1_193_182;
const CHANNEL_2_PORT: u16 = 0x42;
const COMMAND_PORT: u16 = 0x43;
const CONTROL_PORT: u16 = 0x61;

#[derive(Debug)]
pub enum X2ApicError {
    NotSupported,
    NotEnabled,
    EnableFailed,
    InvalidVector,
    ConfigurationFailed,
    TimerError,
    CoreOutOfRange,
}

#[derive(Debug)]
pub enum PitError {
    InvalidDuration,
    CalibrationFailed,
}

static mut APIC_MANAGER: X2ApicManager = X2ApicManager::new();
static CALIBRATED_TIMER_COUNT: AtomicU32 = AtomicU32::new(0);

pub struct X2ApicManager {
    apics: [Option<X2Apic>; MAX_CORES],
}

impl Default for X2ApicManager {
    fn default() -> Self {
        Self::new()
    }
}

impl X2ApicManager {
    pub const fn new() -> Self {
        const NONE_APIC: Option<X2Apic> = None;
        Self {
            apics: [NONE_APIC; MAX_CORES],
        }
    }

    #[inline(always)]
    pub fn current_core_id() -> usize {
        // Change this to not use MSRs
        // Look into storing in CPU specific registers like gs
        unsafe { Msr::new(X2APIC_ID).read() as usize }
    }

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

    pub fn calibrate_timer(hz: u32) -> Result<u32, X2ApicError> {
        let mut pit = Pit::new();
        pit.calibrate_apic_timer(hz)
            .map_err(|_| X2ApicError::TimerError)
    }

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

    #[inline(always)]
    pub fn send_eoi() -> Result<(), X2ApicError> {
        unsafe {
            Msr::new(X2APIC_EOI).write(0);
        }
        Ok(())
    }

    #[inline(always)]
    pub fn mask_timer() -> Result<(), X2ApicError> {
        unsafe {
            let val = Msr::new(X2APIC_LVT_TIMER).read();
            Msr::new(X2APIC_LVT_TIMER).write(val | (1 << 16));
        }
        Ok(())
    }

    #[inline(always)]
    pub fn unmask_timer() -> Result<(), X2ApicError> {
        unsafe {
            let val = Msr::new(X2APIC_LVT_TIMER).read();
            Msr::new(X2APIC_LVT_TIMER).write(val & !(1 << 16));
        }
        Ok(())
    }

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

    pub fn bsp_init(hz: u32) -> Result<(), X2ApicError> {
        // First calibrate the timer
        let count = Self::calibrate_timer(hz)?;
        CALIBRATED_TIMER_COUNT.store(count, Ordering::Release);

        // Then initialize BSP's local APIC
        Self::initialize_current_core()?;
        Self::configure_timer_current_core(count)?;

        Ok(())
    }

    pub fn ap_init() -> Result<(), X2ApicError> {
        let count = CALIBRATED_TIMER_COUNT.load(Ordering::Acquire);
        Self::initialize_current_core()?;
        Self::configure_timer_current_core(count)?;
        Ok(())
    }
}

pub struct X2Apic {
    enabled: bool,
}

impl X2Apic {
    fn new() -> Result<Self, X2ApicError> {
        let cpuid = CpuId::new();
        if !cpuid.get_feature_info().is_some_and(|f| f.has_x2apic()) {
            return Err(X2ApicError::NotSupported);
        }
        Ok(Self { enabled: false })
    }

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
    pub fn new() -> Self {
        Self {
            channel_2: Port::new(CHANNEL_2_PORT),
            command: Port::new(COMMAND_PORT),
            control: Port::new(CONTROL_PORT),
        }
    }

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

pub fn init_bsp(hz: u32) -> Result<(), X2ApicError> {
    X2ApicManager::bsp_init(hz)
}

pub fn init_ap() -> Result<(), X2ApicError> {
    X2ApicManager::ap_init()
}

#[inline(always)]
pub fn send_eoi() {
    X2ApicManager::send_eoi().expect("Failed sending interrupt");
}

#[inline(always)]
pub fn current_core_id() -> usize {
    X2ApicManager::current_core_id()
}

#[inline(always)]
pub fn send_ipi(target_id: u32, vector: u8) {
    X2ApicManager::send_ipi(target_id, vector).expect("Failed sending IPI");
}

#[inline(always)]
pub fn mask_timer() {
    X2ApicManager::mask_timer().expect("Failed to mask timer");
}

#[inline(always)]
pub fn unmask_timer() {
    X2ApicManager::unmask_timer().expect("Failed to unmask timer");
}
