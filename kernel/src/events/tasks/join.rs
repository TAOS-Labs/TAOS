use super::{cancel::CancellationToken, error::TaskError};
use crate::events::EventId;
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use spin::Mutex;

pub struct JoinHandle<T> {
    pub result: Arc<Mutex<Option<Result<T, TaskError>>>>,
    pub waker: Arc<Mutex<Option<Waker>>>,
    pub eid: EventId,
    pub cancellation: CancellationToken,
}

impl<T> JoinHandle<T> {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, TaskError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut result_guard = self.result.lock();
        if let Some(result) = result_guard.take() {
            Poll::Ready(result)
        } else {
            let mut waker_guard = self.waker.lock();
            *waker_guard = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
