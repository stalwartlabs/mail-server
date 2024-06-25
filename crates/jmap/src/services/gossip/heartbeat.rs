/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Peer, State, HEARTBEAT_WINDOW, HEARTBEAT_WINDOW_MASK};
use std::time::Instant;

// Phi Accrual Failure Detector defaults
const HB_MAX_PAUSE_MS: f64 = 0.0;
const HB_MIN_STD_DEV: f64 = 300.0;
const HB_PHI_SUSPECT_THRESHOLD: f64 = 5.0;
const HB_PHI_CONVICT_THRESHOLD: f64 = 9.0;

impl Peer {
    pub fn update_heartbeat(&mut self, is_direct_ping: bool) -> bool {
        let hb_diff =
            std::cmp::min(self.last_heartbeat.elapsed().as_millis(), 60 * 60 * 1000) as u64;
        self.last_heartbeat = Instant::now();

        match self.state {
            State::Seed | State::Offline => {
                tracing::debug!("Peer {} is now alive.", self.addr);
                self.state = State::Alive;

                // Do not count stale heartbeats.
                return true;
            }
            State::Suspected => {
                tracing::debug!("Suspected peer {} was confirmed alive.", self.addr);
                self.state = State::Alive;
            }
            State::Left if is_direct_ping => {
                tracing::debug!(
                    "Peer {} is back online after leaving the cluster.",
                    self.addr
                );
                self.state = State::Alive;

                // Do not count stale heartbeats.
                return true;
            }
            _ => (),
        }

        self.hb_window_pos = (self.hb_window_pos + 1) & HEARTBEAT_WINDOW_MASK;

        if !self.hb_is_full && self.hb_window_pos == 0 && self.hb_sum > 0 {
            self.hb_is_full = true;
        }

        if self.hb_is_full {
            let hb_window = self.hb_window[self.hb_window_pos] as u64;
            self.hb_sum -= hb_window;
            self.hb_sq_sum -= hb_window.saturating_mul(hb_window);
        }

        self.hb_window[self.hb_window_pos] = hb_diff as u32;
        self.hb_sum += hb_diff;
        self.hb_sq_sum += hb_diff.saturating_mul(hb_diff);

        false
    }

    /*
       Phi Accrual Failure Detection
       Ported from https://github.com/akka/akka/blob/main/akka-remote/src/main/scala/akka/remote/PhiAccrualFailureDetector.scala
    */
    pub fn check_heartbeat(&mut self) -> bool {
        if self.hb_sum == 0 {
            return false;
        }

        let hb_diff = self.last_heartbeat.elapsed().as_millis() as f64;
        let sample_size = if self.hb_is_full {
            HEARTBEAT_WINDOW
        } else {
            self.hb_window_pos + 1
        } as f64;
        let hb_mean = (self.hb_sum as f64 / sample_size) + HB_MAX_PAUSE_MS;
        let hb_variance = (self.hb_sq_sum as f64 / sample_size) - (hb_mean * hb_mean);
        let hb_std_dev = hb_variance.sqrt();
        let y = (hb_diff - hb_mean) / hb_std_dev.max(HB_MIN_STD_DEV);
        let e = (-y * (1.5976 + 0.070566 * y * y)).exp();
        let phi = if hb_diff > hb_mean {
            -(e / (1.0 + e)).log10()
        } else {
            -(1.0 - 1.0 / (1.0 + e)).log10()
        };

        /*tracing::debug!(
            "Heartbeat from {}: mean={:.2}ms, variance={:.2}ms, std_dev={:.2}ms, phi={:.2}, samples={}, status={:?}",
            self.addr, hb_mean, hb_variance, hb_std_dev, phi, sample_size, if phi > HB_PHI_CONVICT_THRESHOLD {
                State::Offline
            } else if phi > HB_PHI_SUSPECT_THRESHOLD {
                State::Suspected
            } else {
                State::Alive
            }
        );*/

        if phi > HB_PHI_CONVICT_THRESHOLD {
            tracing::debug!("Peer {} is offline.", self.addr);
            self.state = State::Offline;
            false
        } else if phi > HB_PHI_SUSPECT_THRESHOLD {
            tracing::debug!("Peer {} is suspected to be offline.", self.addr);
            self.state = State::Suspected;
            true
        } else {
            true
        }
    }
}
