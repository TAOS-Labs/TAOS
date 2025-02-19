use super::TaskError;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use spin::Mutex;

#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<Mutex<bool>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(false)),
        }
    }

    pub fn cancel(&self) {
        *self.cancelled.lock() = true;
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock()
    }
}

pub struct CancellationGuard<'a> {
    token: &'a CancellationToken,
}

impl<'a> Future for CancellationGuard<'a> {
    type Output = Result<(), TaskError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.token.is_cancelled() {
            Poll::Ready(Err(TaskError::Cancelled))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
