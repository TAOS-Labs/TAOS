#[repr(transparent)]
pub(crate) struct MMioPtr<T>(pub *mut T);

unsafe impl<T> Send for MMioPtr<T> {}

impl<T> MMioPtr<T> {
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    pub unsafe fn write(&self, val: T) {
        core::ptr::write_volatile(self.0, val);
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0
    }
}

#[repr(transparent)]
pub(crate) struct MMioConstPtr<T>(pub *const T);

unsafe impl<T> Send for MMioConstPtr<T> {}

impl<T> MMioConstPtr<T> {
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const T {
        self.0
    }
}
