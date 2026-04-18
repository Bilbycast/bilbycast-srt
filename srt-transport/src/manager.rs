// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Global socket manager.
//!
//! Maps to C++ `CUDTUnited`. Manages socket lifecycle, ID assignment,
//! and multiplexer allocation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::connection::SrtConnection;

/// Socket identifier type (matches C++ SRTSOCKET = int32_t).
pub type SrtSocketId = i32;

/// Global SRT socket manager.
///
/// Thread-safe registry of all active SRT sockets. Uses an RwLock
/// to allow concurrent reads (most API calls) with exclusive writes
/// (create/close).
pub struct SrtManager {
    /// Socket registry.
    sockets: RwLock<HashMap<SrtSocketId, Arc<SrtConnection>>>,
    /// Socket ID counter (counts backward from random seed, like C++).
    next_id: AtomicI32,
}

impl SrtManager {
    /// Create a new manager.
    pub fn new() -> Self {
        // Start from a random seed in the valid range, like C++
        let seed = rand::random::<i32>().abs().max(1);
        Self {
            sockets: RwLock::new(HashMap::new()),
            next_id: AtomicI32::new(seed),
        }
    }

    /// Generate a unique socket ID.
    fn generate_id(&self) -> SrtSocketId {
        // Simple incrementing; C++ decrements but direction doesn't matter
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let id = (id & 0x3FFF_FFFF).max(1); // Keep in valid range [1, 2^30)
            return id;
        }
    }

    /// Register a connection and return its socket ID.
    pub async fn register(&self, conn: Arc<SrtConnection>) -> SrtSocketId {
        let id = self.generate_id();
        let mut sockets = self.sockets.write().await;
        sockets.insert(id, conn);
        id
    }

    /// Look up a connection by socket ID.
    pub async fn get(&self, id: SrtSocketId) -> Option<Arc<SrtConnection>> {
        let sockets = self.sockets.read().await;
        sockets.get(&id).cloned()
    }

    /// Remove a connection from the registry.
    pub async fn remove(&self, id: SrtSocketId) -> Option<Arc<SrtConnection>> {
        let mut sockets = self.sockets.write().await;
        sockets.remove(&id)
    }

    /// Get the number of active sockets.
    pub async fn socket_count(&self) -> usize {
        let sockets = self.sockets.read().await;
        sockets.len()
    }
}

impl Default for SrtManager {
    fn default() -> Self {
        Self::new()
    }
}
