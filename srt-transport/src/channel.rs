// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! UDP channel wrapper over tokio::net::UdpSocket.
//!
//! Maps to C++ `CChannel`. Provides async send/receive for SRT packets
//! over a single UDP socket.

use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// UDP channel wrapping a tokio UdpSocket.
///
/// A single channel is shared by all SRT sockets on the same UDP port
/// via the multiplexer.
pub struct UdpChannel {
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl UdpChannel {
    /// Create a new UDP channel bound to the given address.
    ///
    /// Enables `SO_REUSEADDR` so that the socket can be rebound quickly
    /// after a connection drops (avoids "address already in use" errors).
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock2 = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        sock2.set_reuse_address(true)?;
        sock2.set_nonblocking(true)?;
        sock2.bind(&addr.into())?;
        let std_socket: std::net::UdpSocket = sock2.into();
        let socket = UdpSocket::from_std(std_socket)?;
        let local_addr = socket.local_addr()?;
        Ok(Self { socket, local_addr })
    }

    /// Create from an existing tokio UdpSocket.
    pub fn from_socket(socket: UdpSocket) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;
        Ok(Self { socket, local_addr })
    }

    /// Get the local address this channel is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a serialized SRT packet to the given address.
    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(data, target).await
    }

    /// Send a packet to a connected peer (for connected UDP sockets).
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send(data).await
    }

    /// Receive a UDP datagram, returning the data length and sender address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// Connect this UDP socket to a specific peer address.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr).await
    }

    /// Set the send buffer size.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        let socket_ref = socket2::SockRef::from(&self.socket);
        socket_ref.set_send_buffer_size(size)?;
        Ok(())
    }

    /// Set the receive buffer size.
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        let socket_ref = socket2::SockRef::from(&self.socket);
        socket_ref.set_recv_buffer_size(size)?;
        Ok(())
    }

    /// Get a reference to the underlying UdpSocket.
    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }
}
