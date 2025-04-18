use core::{future::Future, pin::Pin, task::{Context, Poll}};

use alloc::{boxed::Box, sync::Arc};
use futures::task::ArcWake;
use spin::Mutex;

use crate::events::Event;

/// Future to block an event until a boolean is set to true (by some other event)
pub struct Pawait<R> {
  /// The future the process is awaiting
  future: Mutex<Pin<Box<dyn Future<Output = R> + 'static + Send>>>,
  /// The result of the future
  res: Option<R>, 
  /// The event to block on
  event: Arc<Event>,
}

unsafe impl<R> Send for Pawait<R> {}

impl<R> Pawait<R> {
  /// Create a new Condition
  ///
  /// * `state`: the starting state
  /// * `event`: the relevant event
  pub fn new(fut: impl Future<Output = R> + 'static + Send, event: Arc<Event>) -> Pawait<R> {
    // let fut_ptr: *mut (dyn Future<Output = R>) = Box::pin(fut).into_raw();
    Pawait { future: Mutex::new(Box::pin(fut)), res: None, event }
  }

  /// The associated event is ready to make progress
  pub fn awake(&self) {
      self.event.clone().wake();
  }

  /// Returns the associated event id
  pub fn get_id(&self) -> u64 {
      self.event.eid.0
  }
}

impl<R> Future for Pawait<R> {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut guard = self.future.lock();

    match guard.as_mut().poll(cx) {
      Poll::Ready(rval) => {
        self.as_mut().res = Some(rval);
        Poll::Ready(())
      },
      Poll::Pending => {
        Poll::Pending
      }
    }
  }
}