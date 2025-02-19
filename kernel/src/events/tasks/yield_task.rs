use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub struct Yield {
    yielded: bool,
}

impl Yield {
    pub fn new() -> Self {
        Self { yielded: false }
    }
}

impl Future for Yield {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn yield_now() -> Yield {
    Yield::new()
}
