use crate::prelude::*;
use core::task::{Context, Poll, Waker};
use core::{future::Future, pin::Pin};
use futures::future;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

// BELOW FOR TESTING/DEMONSTRATION PURPOSES

struct RandomFuture {
    prob: f64,
    rng: SmallRng,
    waker: Option<Waker>,
}

impl RandomFuture {
    fn new(prob: f64, seed: u64) -> Self {
        RandomFuture {
            prob,
            rng: SmallRng::seed_from_u64(seed),
            waker: None, // Waker is created upon polling Pending
        }
    }
}

impl Future for RandomFuture {
    type Output = ();

    // Required method
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let prob: f64 = self.prob;
        let res = self.rng.gen_bool(prob);

        let poll = match res {
            true => {
                if let Some(waker) = &self.waker {
                    waker.wake_by_ref();
                };
                Poll::Ready(())
            }
            false => {
                self.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        };

        poll
    }
}

async fn rand_delay(seed: u32) -> u32 {
    serial_println!("Awaiting random delay");
    let rand_task = RandomFuture::new(0.4, seed as u64);
    rand_task.await;
    seed
}

pub async fn print_nums_after_rand_delay(seed: u32) {
    let res = future::join(rand_delay(seed), rand_delay(seed * 2)).await;

    serial_println!("Random results: {} {}", res.0, res.1);
}
