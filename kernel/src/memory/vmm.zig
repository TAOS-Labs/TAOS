const std = @import("std");
const limine = @import("limine");
const serial = @import("../drivers/serial.zig");
const debugPrint = @import("../util.zig").debugPrint;

const PAGE_PRESENT = 0x1;
const PAGE_WRITE = 0x1;
const PAGE_USER = 0x4;

const PAGE_SIZE = 4096;

fn allocate_page() *u64 {
    const page = std.heap.page_allocator.alignedAlloc(u8, PAGE_SIZE, PAGE_SIZE);
    if (page == null) {
        @panic("Failed to allocate page");
    }
    std.mem.set(u8, page, 0);
    return @ptrCast(page); // return as a pointer, is our pte
}

fn setup_page_tables() *u64 {
    // allocate a page for all levels
    const pml4 = allocate_page();
    const pdpt = allocate_page();
    const pd = allocate_page();
    const pt = allocate_page();

    pml4[0] = pdpt;
    pdpt[0] = pd;
    pd[0] = pt;
    const kernel_start = 0x900000;
    const kernel_end = 0x100000;
    var i: usize = 0;
    var addr: usize = kernel_start;

    while (addr < kernel_end) : (addr += PAGE_SIZE) {
        pt[i] = addr | PAGE_PRESENT | PAGE_WRITE;
        i += 1;
    }

    return pml4;
}

pub fn init() void {
    // TODO

}
