use super::cancel::CancellationToken;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use lazy_static::lazy_static;
use raw_cpuid::CpuId;

pub struct TaskContext {
    pub(crate) pid: u32,
    pub(crate) priority: usize,
    pub(crate) cancellation: CancellationToken,
}

// Safe wrapper for Cell that implements Sync
struct SyncCell<T>(Cell<T>);

// Safety: We guarantee that each cell is only accessed by its corresponding CPU
unsafe impl<T> Sync for SyncCell<T> {}

impl<T> SyncCell<T> {
    const fn new(value: T) -> Self {
        Self(Cell::new(value))
    }

    fn replace(&self, value: T) -> T {
        self.0.replace(value)
    }

    fn take(&self) -> T
    where
        T: Default,
    {
        self.0.take()
    }
}

lazy_static! {
    static ref TASK_CONTEXTS: Vec<SyncCell<Option<Box<TaskContext>>>> = {
        let mut v = Vec::with_capacity(32);
        for _ in 0..32 {
            v.push(SyncCell::new(None));
        }
        v
    };
}

pub fn get_current_task() -> Option<&'static TaskContext> {
    let cpuid = CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize;
    if cpuid >= TASK_CONTEXTS.len() {
        return None;
    }

    // Take the current value
    let current = unsafe { TASK_CONTEXTS.get_unchecked(cpuid) }.take();

    // If we have a context, we need to put it back and return a reference
    if let Some(ctx) = current.as_ref() {
        // This is safe because we immediately put the value back
        let static_ref = unsafe { &*(ctx.as_ref() as *const TaskContext) };
        unsafe { TASK_CONTEXTS.get_unchecked(cpuid) }.replace(current);
        Some(static_ref)
    } else {
        None
    }
}

pub fn set_current_task(ctx: Option<Box<TaskContext>>) {
    let cpuid = CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize;
    if cpuid < TASK_CONTEXTS.len() {
        unsafe {
            TASK_CONTEXTS.get_unchecked(cpuid).replace(ctx);
        }
    }
}
