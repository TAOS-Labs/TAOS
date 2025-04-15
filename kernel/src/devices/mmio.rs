#[repr(transparent)]
pub(crate) struct MMioPtr<T>(pub *mut T);

unsafe impl<T> Send for MMioPtr<T> {}

impl<T> MMioPtr<T> {
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    #[allow(dead_code)]
    pub unsafe fn read_unaliged(&self) -> T {
        core::ptr::read_unaligned(self.0)
    }

    pub unsafe fn write(&self, val: T) {
        core::ptr::write_volatile(self.0, val);
    }

    #[allow(dead_code)]
    pub unsafe fn write_unaligned(&self, val: T) {
        core::ptr::write_unaligned(self.0, val);
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0
    }

    pub unsafe fn add<EndType>(&self, offset: usize) -> MMioPtr<EndType> {
        MMioPtr(self.0.add(offset) as *mut EndType)
    }
}

#[repr(transparent)]
pub(crate) struct MMioConstPtr<T>(pub *const T);

unsafe impl<T> Send for MMioConstPtr<T> {}

impl<T> MMioConstPtr<T> {
    #[allow(dead_code)]
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    #[allow(dead_code)]
    pub unsafe fn read_unaligned(&self) -> T {
        core::ptr::read_unaligned(self.0)
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const T {
        self.0
    }

    #[allow(dead_code)]
    pub unsafe fn add<EndType>(&self, offset: usize) -> MMioConstPtr<EndType> {
        MMioConstPtr(self.0.add(offset) as *mut EndType)
    }
}
