use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::marker::PhantomData;

pub struct TaskLocal<T> {
    data: Arc<UnsafeCell<T>>,
    _marker: PhantomData<*const ()>,
}

impl<T> TaskLocal<T> {
    pub fn new(value: T) -> Self {
        Self {
            data: Arc::new(UnsafeCell::new(value)),
            _marker: PhantomData,
        }
    }

    pub fn get(&self) -> &T {
        unsafe { &*self.data.get() }
    }

    pub fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}
