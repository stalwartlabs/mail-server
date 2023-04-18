use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct RateLimiter {
    pub max_requests: f64,
    pub max_interval: f64,
    limiter: (Instant, f64),
}

#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    pub max_concurrent: u64,
    pub concurrent: Arc<AtomicU64>,
}

pub struct InFlight {
    concurrent: Arc<AtomicU64>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl RateLimiter {
    pub fn new(max_requests: u64, max_interval: u64) -> Self {
        RateLimiter {
            max_requests: max_requests as f64,
            max_interval: max_interval as f64,
            limiter: (Instant::now(), max_requests as f64),
        }
    }

    pub fn is_allowed(&mut self) -> bool {
        // Check rate limit
        let elapsed = self.limiter.0.elapsed().as_secs_f64();
        self.limiter.1 += elapsed * (self.max_requests / self.max_interval);
        if self.limiter.1 > self.max_requests {
            self.limiter.1 = self.max_requests;
        }
        if self.limiter.1 >= 1.0 {
            self.limiter.0 = Instant::now();
            self.limiter.1 -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn retry_at(&self) -> Instant {
        Instant::now()
            + Duration::from_secs(
                (self.max_interval as u64).saturating_sub(self.limiter.0.elapsed().as_secs()),
            )
    }

    pub fn elapsed(&self) -> Duration {
        self.limiter.0.elapsed()
    }

    pub fn reset(&mut self) {
        self.limiter = (Instant::now(), self.max_requests);
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter {
            max_concurrent,
            concurrent: Arc::new(0.into()),
        }
    }

    pub fn is_allowed(&self) -> Option<InFlight> {
        if self.concurrent.load(Ordering::Relaxed) < self.max_concurrent {
            // Return in-flight request
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            Some(InFlight {
                concurrent: self.concurrent.clone(),
            })
        } else {
            None
        }
    }

    pub fn check_is_allowed(&self) -> bool {
        self.concurrent.load(Ordering::Relaxed) < self.max_concurrent
    }
}
