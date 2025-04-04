use alloc::{boxed::Box, sync::Arc, vec::Vec};
use async_trait::async_trait;
use spin::Mutex;
use x86_64::{structures::paging::OffsetPageTable, PhysAddr};

use crate::{
    constants::devices::SD_REQ_TIMEOUT_NANOS,
    debug_println,
    devices::pci::write_pci_command,
    events::{current_running_event, futures::devices::SDCardReq, get_runner_time},
    filesys::{BlockDevice, FsError},
};
use bitflags::bitflags;

use super::{
    mmio::map_page_as_uncacheable,
    pci::{read_config, DeviceInfo, PCICommand},
};
/// Used to get access to the sd card in the system. Multiple SD cards
/// are NOT supported
pub static SD_CARD: Mutex<Option<SDCardInfo>> = Mutex::new(Option::None);

#[derive(Debug, Clone)]
/// A struct storing data of an sd card that can be recieved without
/// booting the card.
///
/// SDCardInfo still has data like the relative_card_address that can not be
/// determined until the sd card has somewhat initalized.
struct SDCardInfoInternal {
    /// The contents of the Capabilties register
    capabilities: Capabilities,
    /// The kernel virtual address of the contents of the Base Address Register
    base_address_register: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
/// Represents an SD Card. Is used by all functions that interface with
/// an sd card, and is returned by initalize_sd_card  
pub struct SDCardInfo {
    /// Stores data that can be determined without needing to fully initalize
    /// the card, most importantly the base address register
    internal_info: SDCardInfoInternal,
    /// Stores the block size of this sd card
    block_size: usize,
    /// Stores total blocks of  this sd card
    total_blocks: u64,
    /// Stores the relative card address. This is used as an argument in some
    /// sd commands
    reletave_card_address: u32,
}

#[derive(Debug)]
/// Represents errors that can occur during SD card operation or initalization
pub enum SDCardError {
    /// A command was underway when we tried to send a new command
    CommandInhibited,
    /// Sending a new command failed because there was an error that needs
    /// to be handled first
    CommandStoppedDueToError,
    /// A time out occured when waiting for a response
    SDTimeout,
    /// The sd cards clock frequency could not be set
    FrequencyUnableToBeSet,
    /// The sd cards voltage could not be set
    VoltageUnableToBeSet,
    /// An uncategorized error that could not be better described
    GenericSDError,
}

#[allow(dead_code)]
#[derive(Debug)]
/// Stores the respones of an SD Command. This is fully determined by the
/// response type of the command.
enum SDCommandResponse {
    /// Used when no response is published to the response register
    NoResponse,
    /// Used when the device publishes a 32 bit response to the response
    /// register. This also incluces when the response is in the upper 32 bits
    /// of the register
    Response32Bits(u32),
    /// Used when the device publishes a 128 bit response to the response register
    /// The data in here is shifted 8 bits over as the CRC bits are not sent
    /// to the response register, but they are present in the Physical
    /// Specification, which contains what each bit of the command means.
    Response128Bits(u128),
}

#[allow(dead_code)]
/// The types of response that an SD Command Returns. Even if these
/// say they return the same response type. One should use the appropate
/// response type as this determines which checks get enabled. All response
/// types except for R0 and R2 return a 32 bit response.
enum SDResponseTypes {
    /// Responds as NoRespone
    R0,
    /// Responds as Response128Bits
    R2,
    R1,
    R1b,
    R3,
    R4,
    R5,
    R5b,
    R6,
    R7,
}

bitflags! {
    struct TransferModeFlags: u16 {
        const ResponseInterruptDisable = 1 << 8;
        const ResponseErrorChecKEnable = 1 << 7;
        const ResponseTypeSDIO = 1 << 6;
        const MultipleBlockSelect = 1 << 5;
        const ReadToCard = 1 << 4;
        const BlockCountEnable = 1 << 1;
        const DMAEnable = 1;
        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct Capabilities: u64 {
        const VDD2SSupported = 1 << 60;
        const ADMA3Supported = 1 << 59;
        const SDR50TuningRequired = 1 << 45;
        const DriverTypeDSupprted = 1 << 38;
        const DriverTypeCSupprted = 1 << 37;
        const DriverTypeASupprted = 1 << 36;
        const UHS2Support = 1 << 35;
        const DDR50Support = 1 << 34;
        const SDR104Suppport = 1 << 33;
        const SDR50Support = 1 << 32;
        const AsynchronousInterruptSupport = 1 << 29;
        const SystemAddress64SupportV3Mode = 1 << 28;
        const SystemAddress64SupportV4Mode = 1 << 27;
        const Voltage1_8Support = 1 << 26;
        const Voltage3_0Support = 1 << 25;
        const Voltage3_3Support = 1 << 24;
        const SuspendSupport = 1 << 23;
        const SDMASupport = 1 << 22;
        /// Allows SD clock frequency to go from 25MHZ to 50MHz
        const HighSpeedSupport = 1 << 21;
        const ADMA2Support = 1 << 19;
        const Embedded8bitSupport = 1 << 18;
        /// If not set uses Kkz to set timeout
        const TimeoutClockMhz = 1 << 7;
        const _ = !0;
    }
}

bitflags! {
    #[derive(Clone)]
    pub struct PresentState: u32 {
        const UHS2IFDetection = 1 << 31;
        const LaneSynchronization = 1 << 30;
        const DormantState = 1 << 29;
        const SubCommandStatus = 1 << 28;
        const CommandNotIssuedError = 1 << 27;
        const HostRegulatorVoltageStable = 1 << 25;
        const CMDLineSignalLevel = 1 << 24;
        const WriteEnabled  = 1 << 19;
        const CardPresent = 1 << 18;
        const CardStateStable = 1 << 17;
        const CardInserted = 1 << 16;
        const BufferReadEnable = 1 << 11;
        const BufferWriteEnable = 1 << 10;
        const ReadTransferActive = 1 << 9;
        const WriteTransferActive = 1 << 8;
        const RetuningRequest = 1 << 3;
        const DATLineActive = 1 << 2;
        const CommandInhibitData = 1 << 1;
        const CommandInhibitCmd = 1;
        const _ = !0;
    }
}

bitflags! {
    struct CommandFlags: u16 {
        const DataPresentSelect = 1 << 5;
        const CommandIndexCheckEnable = 1 << 4;
        const CommandCRCCheckEnable = 1 << 3;
        const SubCommandFlag = 1 << 2;
        const _ = !0;
    }
}

const SD_CLASS_CODE: u8 = 0x8;
const SD_SUB_CLASS: u8 = 0x5;
const SD_NO_DMA_INTERFACE: u8 = 0x0;
const SD_DMA_INTERFACE: u8 = 0x1;
const MAX_ITERATIONS: usize = 1_000;
const SD_BLOCK_SIZE: u32 = 512;

#[async_trait]
impl BlockDevice for SDCardInfo {
    async fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<(), FsError> {
        if block_num > self.total_blocks {
            return Result::Err(FsError::IOError);
        }
        let data = read_sd_card(
            self,
            block_num
                .try_into()
                .expect("Maxumum block number should not be greater than 32 bits"),
        )
        .await
        .map_err(|_| FsError::IOError)?;
        buf.copy_from_slice(&data);

        Result::Ok(())
    }

    async fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), FsError> {
        if block_num > self.total_blocks {
            return Result::Err(FsError::IOError);
        }
        let mut data: [u8; 512] = [0; 512];
        data.copy_from_slice(buf);
        write_sd_card(
            self,
            block_num
                .try_into()
                .expect("Maximum block number should not be greater than 32 bits"),
            data,
        )
        .await
        .map_err(|_| FsError::IOError)?;
        Result::Ok(())
    }

    fn block_size(&self) -> usize {
        SD_BLOCK_SIZE.try_into().expect("To be on 64 bit system")
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }
}

/// Finds the FIRST device that represents an SD card, or returns None if
/// this was not found. Most functions take in SDCard Info struct, which
/// can be recieved by using initalize_sd_card with the SD card that
/// was found using this function.
pub fn find_sd_card(devices: &Vec<Arc<Mutex<DeviceInfo>>>) -> Option<Arc<Mutex<DeviceInfo>>> {
    for possible_device in devices {
        let arc_device = possible_device.clone();
        let device = arc_device.lock();
        if device.class_code == SD_CLASS_CODE
            && device.subclass == SD_SUB_CLASS
            && (device.programming_interface == SD_DMA_INTERFACE
                || device.programming_interface == SD_NO_DMA_INTERFACE)
        {
            return Option::Some(possible_device.clone());
        }
    }
    Option::None
}

/// Sets up an sd card, returning an SDCardInfo that can be used for further
/// accesses to the sd card
/// THIS ASSUMES A VERSION 2 SDCARD as of writing
pub fn initalize_sd_card(
    sd_arc: &Arc<Mutex<DeviceInfo>>,
    mapper: &mut OffsetPageTable,
) -> Result<(), SDCardError> {
    // Assume sd_card is a device info for an SD Crd
    // Lets assume 1 slot, and it uses BAR 1

    // Disable Commands from being sent over the Memory Space
    let sd_lock = sd_arc.clone();
    let sd_card = sd_lock.lock();
    let command = sd_card.command & !PCICommand::MEMORY_SPACE;
    write_pci_command(sd_card.bus, sd_card.device, 0, command);

    // Determine the Base Address, and setup a mapping
    let base_address_register = read_config(sd_card.bus, sd_card.device, 0, 0x10);
    let bar_address: u64 = (base_address_register & 0xFFFFFF00).into();
    let base_virtual_addr = map_page_as_uncacheable(PhysAddr::new(bar_address), mapper)
        .map_err(|_| SDCardError::GenericSDError)?;
    let offset_bar = base_virtual_addr.as_u64();
    // Re-enable memory space commands
    write_pci_command(
        sd_card.bus,
        sd_card.device,
        0,
        sd_card.command | PCICommand::MEMORY_SPACE | PCICommand::BUS_MASTER,
    );
    // Store capabilities in capabilties register
    let capablities = unsafe { core::ptr::read_volatile((offset_bar + 0x40) as *const u64) };

    // Construct the stuct that we will use for further communication
    let info = SDCardInfoInternal {
        capabilities: Capabilities::from_bits_retain(capablities),
        base_address_register: offset_bar,
    };

    let new_info = reset_sd_card(&info)?;
    *SD_CARD.lock() = Option::Some(new_info);
    Result::Ok(())
}

/// Sends a software reset to the sd card using the reset register
fn software_reset_sd_card(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let reset_addr = (sd_card.base_address_register + 0x2f) as *mut u8;
    unsafe { core::ptr::write_volatile(reset_addr, 1) };

    // Wait for reset to set in TODO: Remove spin
    let mut finished = false;
    for _ in 0..MAX_ITERATIONS {
        let reset_taken = unsafe { core::ptr::read_volatile(reset_addr) };
        if reset_taken & 1 == 0 {
            finished = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !finished {
        debug_println!("Reset Failed");
        return Result::Err(SDCardError::SDTimeout);
    }
    Result::Ok(())
}

/// Enables most interrupts of the sd card
///
/// Curently we do not have an interrupt handler set up
fn enable_sd_card_interrupts(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let normal_intr_status_addr = (sd_card.base_address_register + 0x34) as *mut u16;
    unsafe { core::ptr::write_volatile(normal_intr_status_addr, 0x1FF) };
    sending_command_valid(sd_card)?;
    let error_intr_status_addr = (sd_card.base_address_register + 0x36) as *mut u16;
    unsafe { core::ptr::write_volatile(error_intr_status_addr, 0x0FB) };
    sending_command_valid(sd_card)?;
    let normal_intr_enable_addr = (sd_card.base_address_register + 0x38) as *mut u16;
    unsafe { core::ptr::write_volatile(normal_intr_enable_addr, 0x1FF) };
    sending_command_valid(sd_card)?;
    let error_intr_enable_addr = (sd_card.base_address_register + 0x3A) as *mut u16;
    unsafe { core::ptr::write_volatile(error_intr_enable_addr, 0x0FB) };
    sending_command_valid(sd_card)?;
    Result::Ok(())
}

/// Determines what voltages the sd card supports, and enables power
/// to the sd card
fn power_on_sd_card(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let power_control_addr = (sd_card.base_address_register + 0x29) as *mut u8;
    // Turn off power so we can change the voltage
    unsafe { core::ptr::write_volatile(power_control_addr, 0) };
    // Use maximum voltage that capabiltieis shows
    let mut power_control;
    if Capabilities::Voltage3_3Support.intersects(sd_card.capabilities) {
        power_control = 0b111 << 1;
    } else if Capabilities::Voltage1_8Support.intersects(sd_card.capabilities) {
        power_control = 0b101 << 1;
    } else if Capabilities::Voltage3_0Support.intersects(sd_card.capabilities) {
        power_control = 0b110 << 1;
    } else {
        return Result::Err(SDCardError::VoltageUnableToBeSet);
    }
    unsafe { core::ptr::write_volatile(power_control_addr, power_control) };
    power_control |= 1;
    unsafe { core::ptr::write_volatile(power_control_addr, power_control) };
    Result::Ok(())
}

/// Determines the sd clock divisor to set, and turns the clock on
fn set_sd_clock(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let clock_ctrl_reg_addr = (sd_card.base_address_register + 0x2c) as *mut u16;
    // Disable sd_clock so we can change it
    let mut clock_ctrl_reg = unsafe { core::ptr::read_volatile(clock_ctrl_reg_addr) };
    clock_ctrl_reg &= 0xFFFE;
    unsafe { core::ptr::write_volatile(clock_ctrl_reg_addr, clock_ctrl_reg) };

    // TODO check if actural hardware supports PLL enable (if so unset it too)
    clock_ctrl_reg &= 0x00FF;
    clock_ctrl_reg |= 0x80 << 8;
    // clock_ctrl_reg |= divisor_extended << 8;
    unsafe { core::ptr::write_volatile(clock_ctrl_reg_addr, clock_ctrl_reg) };
    // Enable internal clock
    clock_ctrl_reg |= 1;
    unsafe { core::ptr::write_volatile(clock_ctrl_reg_addr, clock_ctrl_reg) };

    // Wait for stability
    let mut finished = false;
    for _ in 0..MAX_ITERATIONS {
        let clock_taken = unsafe { core::ptr::read_volatile(clock_ctrl_reg_addr) };
        if clock_taken & 0b10 != 0 {
            finished = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !finished {
        debug_println!("Clock set Failed");
        return Result::Err(SDCardError::SDTimeout);
    }
    // Now we can enable the SD clock
    clock_ctrl_reg |= 0b11 << 1;
    unsafe { core::ptr::write_volatile(clock_ctrl_reg_addr, clock_ctrl_reg) };

    Result::Ok(())
}

/// Sets up the timeouts on the sd card to be sent after the most time has passed
fn enable_timeouts(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let timeout_addr = (sd_card.base_address_register + 0x2e) as *mut u8;
    unsafe { core::ptr::write_volatile(timeout_addr, 0b1110) };
    sending_command_valid(sd_card)?;
    Result::Ok(())
}

/// Resets and initallizes an sd card using only sd card commands
fn send_sd_reset_commands(sd_card: &SDCardInfoInternal) -> Result<SDCardInfo, SDCardError> {
    // Send cmd 0
    let mut result = Result::Err(SDCardError::GenericSDError);
    let argument_register_addr = (sd_card.base_address_register + 0x8) as *mut u32;
    unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
    send_sd_command(sd_card, 0, SDResponseTypes::R0, CommandFlags::empty())?;
    // CMD 8
    let argument_register_addr = (sd_card.base_address_register + 0x8) as *mut u32;
    // TODO fix: Hard code voltage in 2.7-3.8v
    // check pattern = 0xaa
    unsafe { core::ptr::write_volatile(argument_register_addr, 0x1aa) };
    send_sd_command(sd_card, 8, SDResponseTypes::R7, CommandFlags::empty())?;
    // CMD 55
    unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
    send_sd_command(sd_card, 55, SDResponseTypes::R1, CommandFlags::empty())?;

    // ACMD 41 (Inquiry)
    let acmd_response_enum =
        send_sd_command(sd_card, 41, SDResponseTypes::R3, CommandFlags::empty())?;
    if let SDCommandResponse::Response32Bits(acmd_response) = acmd_response_enum {
        unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
        send_sd_command(sd_card, 0, SDResponseTypes::R0, CommandFlags::empty())?;
        // CMD 8
        let argument_register_addr = (sd_card.base_address_register + 0x8) as *mut u32;
        // TODO fix: Hard code voltage in 2.7-3.8v
        // check pattern = 0xaa
        unsafe { core::ptr::write_volatile(argument_register_addr, 0x1aa) };
        send_sd_command(sd_card, 8, SDResponseTypes::R7, CommandFlags::empty())?;
        // CMD 55
        unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
        send_sd_command(sd_card, 55, SDResponseTypes::R1, CommandFlags::empty())?;

        // ACMD 41 (Inquiry)
        let mut new_acmd_response = acmd_response & 0xFF;
        // Enable sdhc
        new_acmd_response |= 1 << 22;
        unsafe { core::ptr::write_volatile(argument_register_addr, new_acmd_response) };
        send_sd_command(sd_card, 41, SDResponseTypes::R3, CommandFlags::empty())?;
    } else {
        panic!("ACMD should return a 32 bit response")
    }

    // cmd 2

    unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
    send_sd_command(sd_card, 2, SDResponseTypes::R2, CommandFlags::empty())?;
    // cmd 3
    unsafe { core::ptr::write_volatile(argument_register_addr, 0) };
    let rca_enum = send_sd_command(sd_card, 3, SDResponseTypes::R6, CommandFlags::empty())?;
    if let SDCommandResponse::Response32Bits(rca) = rca_enum {
        unsafe { core::ptr::write_volatile(argument_register_addr, rca) };
        let csd_enum = send_sd_command(sd_card, 9, SDResponseTypes::R2, CommandFlags::empty())?;
        if let SDCommandResponse::Response128Bits(csd) = csd_enum {
            let actual_info = get_full_sd_card_info(sd_card, rca, csd)?;
            result = Result::Ok(actual_info);
        }

        unsafe { core::ptr::write_volatile(argument_register_addr, rca) };
        send_sd_command(sd_card, 13, SDResponseTypes::R1, CommandFlags::empty())?;

        // Sebd cnd 7 to set transfer state
        unsafe { core::ptr::write_volatile(argument_register_addr, rca) };
        send_sd_command(sd_card, 7, SDResponseTypes::R1b, CommandFlags::empty())?;
    } else {
        panic!("CMD 3 should return a 32 bit response");
    }

    result
}

/// Creates an SDCardInfo from the provided data
fn get_full_sd_card_info(
    sd_card: &SDCardInfoInternal,
    rca: u32,
    csd: u128,
) -> Result<SDCardInfo, SDCardError> {
    // Currently only supports CSD Version 1.0
    let csd_structre: u32 = (csd >> 126)
        .try_into()
        .expect("Higher bits to be masked out");
    assert!(
        csd_structre == 1,
        "Only SDHC and SDXC cards are supported as of this moment"
    );
    let c_size: u32 = ((csd >> 48) & 0xFFFFFF)
        .try_into()
        .expect("Higher bits should be masked out");

    let info = SDCardInfo {
        internal_info: sd_card.clone(),
        reletave_card_address: rca,
        block_size: SD_BLOCK_SIZE.try_into().expect("To be on 64 bit system"),
        total_blocks: (c_size + 1).into(),
    };

    Result::Ok(info)
}

/// Preforms the steps to reset and initalize an sd card, returning the completed
/// struct
fn reset_sd_card(sd_card: &SDCardInfoInternal) -> Result<SDCardInfo, SDCardError> {
    software_reset_sd_card(sd_card)?;
    enable_sd_card_interrupts(sd_card)?;
    power_on_sd_card(sd_card)?;
    set_sd_clock(sd_card)?;
    // Is this needed, should this be here if so
    enable_timeouts(sd_card)?;

    let info = send_sd_reset_commands(sd_card)?;

    Result::Ok(info)
}

// Determines if sending a command is currently valid
fn sending_command_valid(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    check_no_errors(sd_card)?;
    let present_state_register_addr = (sd_card.base_address_register + 0x24) as *const u32;
    let present_state = unsafe { core::ptr::read_volatile(present_state_register_addr) };
    let inhibited_state = PresentState::CommandInhibitCmd | PresentState::CommandInhibitData;
    if inhibited_state.intersects(PresentState::from_bits_retain(present_state)) {
        return Result::Err(SDCardError::CommandInhibited);
    }
    if PresentState::CommandNotIssuedError.contains(PresentState::from_bits_retain(present_state)) {
        debug_println!("Present state = 0x{present_state:X}");
        return Result::Err(SDCardError::CommandStoppedDueToError);
    }
    Result::Ok(())
}

/// Asserts that there are no errors in the error state register
fn check_no_errors(sd_card: &SDCardInfoInternal) -> Result<(), SDCardError> {
    let error_state_intr_addr = (sd_card.base_address_register + 0x32) as *const u16;
    let error_state = unsafe { core::ptr::read_volatile(error_state_intr_addr) };
    if error_state != 0 {
        debug_println!("Error detected 0x{error_state:x}");
        // TODO: Give better error
        return Result::Err(SDCardError::GenericSDError);
    }

    Result::Ok(())
}

/// Bugs: Does not currently work with cmd 12 or 23 (gets response in wrong place)
/// Also Response type r7 does not seem to be documented
fn send_sd_command(
    sd_card: &SDCardInfoInternal,
    command_idx: u8,
    respone_type: SDResponseTypes,
    flags: CommandFlags,
) -> Result<SDCommandResponse, SDCardError> {
    assert!(command_idx < 64);
    sending_command_valid(sd_card)?;

    let command_register_addr = (sd_card.base_address_register + 0xE) as *mut u16;
    let mut command: u16 = command_idx.into();
    command <<= 8;
    let mut myflags = CommandFlags::from_bits_retain(flags.bits());
    match respone_type {
        SDResponseTypes::R2 => {
            command |= 0b01;
            myflags |= CommandFlags::CommandCRCCheckEnable
        }
        SDResponseTypes::R3 | SDResponseTypes::R4 => {
            command |= 0b10;
        }
        SDResponseTypes::R1 | SDResponseTypes::R5 | SDResponseTypes::R7 | SDResponseTypes::R6 => {
            command |= 0b10;
            myflags |= CommandFlags::CommandIndexCheckEnable | CommandFlags::CommandCRCCheckEnable;
        }
        SDResponseTypes::R1b | SDResponseTypes::R5b => {
            command |= 0b11;
            myflags |= CommandFlags::CommandIndexCheckEnable | CommandFlags::CommandCRCCheckEnable;
        }
        _ => (),
    }
    command |= myflags.bits();
    sending_command_valid(sd_card)?;
    unsafe { core::ptr::write_volatile(command_register_addr, command) };
    check_no_errors(sd_card)?;
    let interrupt_status_register = (sd_card.base_address_register + 0x30) as *mut u16;
    for _ in 0..MAX_ITERATIONS {
        unsafe {
            let command_done = core::ptr::read_volatile(interrupt_status_register);
            if (command_done & 1) == 1 {
                core::ptr::write_volatile(interrupt_status_register, 1);
                return Result::Ok(determine_sd_card_response(sd_card, respone_type));
            } else if command_done != 0 {
                debug_println!("Something happened 0x{command_done:X}");
            }

            core::hint::spin_loop();
        }
    }
    check_no_errors(sd_card)?;
    Result::Err(SDCardError::SDTimeout)
}

/// Returns the data in the SD Cards response register
fn determine_sd_card_response(
    sd_card: &SDCardInfoInternal,
    respone_type: SDResponseTypes,
) -> SDCommandResponse {
    match respone_type {
        SDResponseTypes::R1b
        | SDResponseTypes::R1
        | SDResponseTypes::R3
        | SDResponseTypes::R4
        | SDResponseTypes::R5b
        | SDResponseTypes::R5
        | SDResponseTypes::R6 => {
            let response_register = (sd_card.base_address_register + 0x10) as *const u32;
            let response = unsafe { core::ptr::read_volatile(response_register) };
            SDCommandResponse::Response32Bits(response)
        }
        SDResponseTypes::R2 => {
            let mut response: u128 = 0;
            let response_register = (sd_card.base_address_register + 0x10) as *const u32;
            let response_32_bits: u128 =
                unsafe { core::ptr::read_volatile(response_register).into() };
            response |= response_32_bits;
            let response_register = (sd_card.base_address_register + 0x14) as *const u32;
            let response_32_bits: u128 =
                unsafe { core::ptr::read_volatile(response_register).into() };
            response |= response_32_bits << 32;
            let response_register = (sd_card.base_address_register + 0x18) as *const u32;
            let response_32_bits: u128 =
                unsafe { core::ptr::read_volatile(response_register).into() };
            response |= response_32_bits << 64;
            let response_register = (sd_card.base_address_register + 0x1C) as *const u32;
            let response_32_bits: u128 =
                unsafe { core::ptr::read_volatile(response_register).into() };
            response |= response_32_bits << 96;
            response <<= 8;
            SDCommandResponse::Response128Bits(response)
        }
        _ => SDCommandResponse::NoResponse,
    }
}

/// Reads data from a sd card, returning it as  a return value unless an Error
/// Occurred
pub async fn read_sd_card(sd_card: &SDCardInfo, block: u32) -> Result<[u8; 512], SDCardError> {
    let internal_info = &sd_card.internal_info;
    let block_size_register_addr = (internal_info.base_address_register + 0x4) as *mut u16;
    unsafe { core::ptr::write_volatile(block_size_register_addr, 0x200) };
    let block_count_register_addr = (internal_info.base_address_register + 0x6) as *mut u16;
    unsafe { core::ptr::write_volatile(block_count_register_addr, 1) };
    sending_command_valid(internal_info)?;
    let argument_register_addr = (internal_info.base_address_register + 0x8) as *mut u32;
    unsafe { core::ptr::write_volatile(argument_register_addr, block * SD_BLOCK_SIZE) };
    let transfer_mode_register_adder = (internal_info.base_address_register + 0xC) as *mut u16;
    unsafe {
        core::ptr::write_volatile(
            transfer_mode_register_adder,
            TransferModeFlags::ReadToCard.bits(),
        )
    };

    // Send command
    send_sd_command(
        internal_info,
        17,
        SDResponseTypes::R1,
        CommandFlags::DataPresentSelect,
    )?;

    // TODO SD Card lock for safety? (OR at least for this mem address)
    let present_state_register_addr = (internal_info.base_address_register + 0x24) as *const u32;

    let read_ready = SDCardReq::new(
        PresentState::BufferReadEnable,
        present_state_register_addr,
        get_runner_time(SD_REQ_TIMEOUT_NANOS),
        current_running_event().expect("Reading from SD outside event"),
    )
    .await;

    if read_ready.is_err() {
        debug_println!("Timedout");
        return Result::Err(SDCardError::SDTimeout);
    }

    let mut data = [0; 128];
    let buffer_data_port_reg_addr = (internal_info.base_address_register + 0x20) as *const u32;
    for item in &mut data {
        *item = unsafe { core::ptr::read_volatile(buffer_data_port_reg_addr) };
    }

    let new_data = unsafe { core::mem::transmute::<[u32; 128], [u8; 512]>(data) };
    Result::Ok(new_data)
}

/// Writes data to block of sd card
pub async fn write_sd_card(
    sd_card: &SDCardInfo,
    block: u32,
    data: [u8; 512],
) -> Result<(), SDCardError> {
    let internal_info = &sd_card.internal_info;
    let block_size_register_addr = (internal_info.base_address_register + 0x4) as *mut u16;
    unsafe { core::ptr::write_volatile(block_size_register_addr, 0x200) };
    let block_count_register_addr = (internal_info.base_address_register + 0x6) as *mut u16;
    unsafe { core::ptr::write_volatile(block_count_register_addr, 1) };
    sending_command_valid(internal_info)?;
    let argument_register_addr = (internal_info.base_address_register + 0x8) as *mut u32;
    unsafe { core::ptr::write_volatile(argument_register_addr, block * SD_BLOCK_SIZE) };
    let transfer_mode_register_adder = (internal_info.base_address_register + 0xC) as *mut u16;
    unsafe { core::ptr::write_volatile(transfer_mode_register_adder, 0) };

    // Send command
    send_sd_command(
        internal_info,
        24,
        SDResponseTypes::R1,
        CommandFlags::DataPresentSelect,
    )?;

    let present_state_register_addr = (internal_info.base_address_register + 0x24) as *const u32;

    let write_ready = SDCardReq::new(
        PresentState::BufferWriteEnable,
        present_state_register_addr,
        get_runner_time(SD_REQ_TIMEOUT_NANOS),
        current_running_event().expect("Writing to SD outside event"),
    )
    .await;

    if write_ready.is_err() {
        debug_println!("Timedout");
        return Result::Err(SDCardError::SDTimeout);
    }

    let data_32_bits: [u32; 128] = unsafe { core::mem::transmute(data) };
    let buffer_data_port_reg_addr = (internal_info.base_address_register + 0x20) as *mut u32;
    for item in data_32_bits {
        unsafe {
            core::ptr::write_volatile(buffer_data_port_reg_addr, item);
        }
    }

    Result::Ok(())
}
