use crate::{
    debug,
    events::{current_running_event_info, EventInfo},
    interrupts::x2apic,
    processes::process::{clear_process_frames, sleep_process, ProcessState, PROCESS_TABLE},
};

pub fn sys_exit() {
    // TODO handle hierarchy (parent processes), resources, threads, etc.
    // TODO recursive page table walk to handle cleaning up process memory
    let event: EventInfo = current_running_event_info();

    if event.pid == 0 {
        panic!("Calling exit from outside of process");
    }

    debug!("Process {} exit", event.pid);

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Terminated;
        clear_process_frames(&mut *pcb);
        process_table.remove(&event.pid);
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            "ret",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );
    }
}

pub fn sys_nanosleep(nanos: u64, rsp: u64) {
    sleep_process(rsp, nanos);
    x2apic::send_eoi();
}
