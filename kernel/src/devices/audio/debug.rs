use crate::{
    devices::audio::hda_regs::{HdaRegisters, StreamDescriptor},
    serial_println,
};
use core::mem::size_of;

/// Helper to print field offset relative to struct base
fn print_field_offset<T, F>(base: &T, field: &F, name: &str) {
    let base_ptr = base as *const T as usize;
    let field_ptr = field as *const F as usize;
    let offset = field_ptr - base_ptr;
    serial_println!("{:>25}: 0x{:X}", name, offset);
}

/// Call this from `init()` or `test_dma_transfer()` to verify layout
pub fn debug_hda_register_layout(regs: &HdaRegisters) {
    serial_println!("===== HDA Register Layout Debug (Safe Rust) =====");

    serial_println!("--- HdaRegisters ---");
    print_field_offset(regs, &regs.gcap, "gcap");
    print_field_offset(regs, &regs.vmin, "vmin");
    print_field_offset(regs, &regs.vmaj, "vmaj");
    print_field_offset(regs, &regs.outpay, "outpay");
    print_field_offset(regs, &regs.inpay, "inpay");
    print_field_offset(regs, &regs.gctl, "gctl");
    print_field_offset(regs, &regs.wakeen, "wakeen");
    print_field_offset(regs, &regs.statests, "statests");
    print_field_offset(regs, &regs.gsts, "gsts");
    print_field_offset(regs, &regs.outstrmpay, "outstrmpay");
    print_field_offset(regs, &regs.instrmpay, "instrmpay");
    print_field_offset(regs, &regs.intctl, "intctl");
    print_field_offset(regs, &regs.intsts, "intsts");
    print_field_offset(regs, &regs.walclk, "walclk");
    print_field_offset(regs, &regs.ssync, "ssync");
    print_field_offset(regs, &regs.corblbase, "corblbase");
    print_field_offset(regs, &regs.corbubase, "corbubase");
    print_field_offset(regs, &regs.corbwp, "corbwp");
    print_field_offset(regs, &regs.corbrp, "corbrp");
    print_field_offset(regs, &regs.corbctl, "corbctl");
    print_field_offset(regs, &regs.corbsts, "corbsts");
    print_field_offset(regs, &regs.corbsize, "corbsize");
    print_field_offset(regs, &regs.rirblbase, "rirblbase");
    print_field_offset(regs, &regs.rirbubase, "rirbubase");
    print_field_offset(regs, &regs.rirbwp, "rirbwp");
    print_field_offset(regs, &regs.rirbctl, "rirbctl");
    print_field_offset(regs, &regs.rirbsts, "rirbsts");
    print_field_offset(regs, &regs.rirbsize, "rirbsize");
    print_field_offset(regs, &regs.icoi, "icoi");
    print_field_offset(regs, &regs.icii, "icii");
    print_field_offset(regs, &regs.icis, "icis");
    print_field_offset(regs, &regs.dplbase, "dplbase");
    print_field_offset(regs, &regs.dpubase, "dpubase");
    print_field_offset(regs, &regs.stream_regs, "stream_regs");

    serial_println!("Size of HdaRegisters: 0x{:X}", size_of::<HdaRegisters>());

    serial_println!("--- StreamDescriptor ---");

    let dummy = StreamDescriptor {
        ctl: 0,
        sts: 0,
        lpib: 0,
        cbl: 0,
        lvi: 0,
        reserved: 0,
        fmt: 0,
        reserved2: 0,
        bdlpl: 0,
        bdlpu: 0,
    };

    print_field_offset(&dummy, &dummy.ctl, "ctl");
    print_field_offset(&dummy, &dummy.sts, "sts");
    print_field_offset(&dummy, &dummy.lpib, "lpib");
    print_field_offset(&dummy, &dummy.cbl, "cbl");
    print_field_offset(&dummy, &dummy.lvi, "lvi");
    print_field_offset(&dummy, &dummy.reserved, "reserved");
    print_field_offset(&dummy, &dummy.fmt, "fmt");
    print_field_offset(&dummy, &dummy.reserved2, "reserved2");
    print_field_offset(&dummy, &dummy.bdlpl, "bdlpl");
    print_field_offset(&dummy, &dummy.bdlpu, "bdlpu");

    serial_println!(
        "Size of StreamDescriptor: 0x{:X}",
        size_of::<StreamDescriptor>()
    );
    serial_println!("======================================================");
}
