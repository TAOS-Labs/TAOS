use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub struct Yield {
    yielded: bool,
}

impl Yield {
    pub fn new() -> Self {
        Self { yielded: false }
    }
}

impl Default for Yield {
    fn default() -> Self {
        Self::new()
    }
}

impl Future for Yield {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            Poll::Pending
        }
    }
}

pub fn yield_now() -> Yield {
    Yield::new()
}
