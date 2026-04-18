// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT-level event notification.
//!
//! Maps to C++ `CEPoll`. Provides async event watching for
//! SRT sockets (readable, writable, error conditions).

use std::collections::HashMap;

use bitflags::bitflags;
use tokio::sync::{Mutex, Notify};

use crate::manager::SrtSocketId;

bitflags! {
    /// SRT epoll event flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SrtEpollOpt: u32 {
        /// Socket is ready for reading.
        const IN = 0x01;
        /// Socket is ready for writing.
        const OUT = 0x04;
        /// Socket has an error condition.
        const ERR = 0x08;
        /// Edge-triggered mode for IN events.
        const ET_IN = 0x10;
        /// Edge-triggered mode for OUT events.
        const ET_OUT = 0x20;
        /// Edge-triggered mode for ERR events.
        const ET_ERR = 0x40;
        /// Update existing subscription (don't replace).
        const UPDATE = 0x80;
    }
}

/// Event ready on a socket.
#[derive(Debug, Clone, Copy)]
pub struct SrtEpollEvent {
    /// The socket ID this event relates to.
    pub socket_id: SrtSocketId,
    /// The events that are ready.
    pub events: SrtEpollOpt,
}

/// Watch entry for a socket.
struct WatchEntry {
    /// Subscribed events.
    watch: SrtEpollOpt,
    /// Current ready events.
    ready: SrtEpollOpt,
}

/// SRT epoll instance.
///
/// Watches a set of SRT sockets for readability, writability, and errors.
pub struct SrtEpoll {
    /// Socket subscriptions.
    watches: Mutex<HashMap<SrtSocketId, WatchEntry>>,
    /// Notification when events become available.
    notify: Notify,
}

impl SrtEpoll {
    /// Create a new epoll instance.
    pub fn new() -> Self {
        Self {
            watches: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        }
    }

    /// Subscribe a socket for events.
    pub async fn add(&self, socket_id: SrtSocketId, events: SrtEpollOpt) {
        let mut watches = self.watches.lock().await;
        watches.insert(socket_id, WatchEntry {
            watch: events,
            ready: SrtEpollOpt::empty(),
        });
    }

    /// Update subscription for a socket.
    pub async fn update(&self, socket_id: SrtSocketId, events: SrtEpollOpt) {
        let mut watches = self.watches.lock().await;
        if let Some(entry) = watches.get_mut(&socket_id) {
            entry.watch = events;
        }
    }

    /// Remove a socket from this epoll.
    pub async fn remove(&self, socket_id: SrtSocketId) {
        let mut watches = self.watches.lock().await;
        watches.remove(&socket_id);
    }

    /// Signal that events are ready on a socket.
    ///
    /// Called internally when socket state changes (e.g., data received,
    /// send buffer space freed, error occurred).
    pub async fn update_events(&self, socket_id: SrtSocketId, events: SrtEpollOpt) {
        let mut watches = self.watches.lock().await;
        if let Some(entry) = watches.get_mut(&socket_id) {
            let relevant = events & entry.watch;
            if !relevant.is_empty() {
                entry.ready |= relevant;
                drop(watches);
                self.notify.notify_waiters();
            }
        }
    }

    /// Wait for events on subscribed sockets.
    ///
    /// Returns ready events, blocking until at least one event is available
    /// or the timeout expires.
    pub async fn wait(&self, timeout: std::time::Duration) -> Vec<SrtEpollEvent> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Check for ready events
            let events = self.collect_ready().await;
            if !events.is_empty() {
                return events;
            }

            // Wait for notification or timeout
            tokio::select! {
                _ = self.notify.notified() => {
                    // Check again
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Vec::new();
                }
            }
        }
    }

    /// Collect and clear ready events.
    async fn collect_ready(&self) -> Vec<SrtEpollEvent> {
        let mut watches = self.watches.lock().await;
        let mut events = Vec::new();

        for (&socket_id, entry) in watches.iter_mut() {
            if !entry.ready.is_empty() {
                events.push(SrtEpollEvent {
                    socket_id,
                    events: entry.ready,
                });
                // Clear level-triggered events
                // Keep edge-triggered events until explicitly cleared
                let edge_mask = SrtEpollOpt::ET_IN | SrtEpollOpt::ET_OUT | SrtEpollOpt::ET_ERR;
                if entry.watch.intersects(edge_mask) {
                    // Edge-triggered: clear reported events
                    entry.ready = SrtEpollOpt::empty();
                }
                // Level-triggered: keep events set (will be reported again)
            }
        }

        events
    }
}

impl Default for SrtEpoll {
    fn default() -> Self {
        Self::new()
    }
}
