/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::SymmetricEncrypt;
use crate::JmapInstance;

use super::request::Request;
use super::{Gossiper, Peer, UDP_MAX_PAYLOAD};
use common::IPC_CHANNEL_BUFFER;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::watch;
use tokio::{net::UdpSocket, sync::mpsc};
use utils::config::Config;

pub struct GossiperBuilder {
    bind_addr: IpAddr,
    advertise_addr: IpAddr,
    port: u16,
    cluster_key: String,
    peers: Vec<Peer>,
    ping_interval: Duration,
}

//  Quidnunc: an inquisitive and gossipy person, from Latin quid nunc? 'what now?'.
struct Quidnunc {
    socket: UdpSocket,
    nonce: Vec<u8>,
    encryptor: SymmetricEncrypt,
}

impl GossiperBuilder {
    pub fn try_parse(config: &mut Config) -> Option<Self> {
        // Load configuration
        let bind_addr = config.property::<IpAddr>("cluster.bind-addr")?;
        let mut builder = GossiperBuilder {
            bind_addr,
            cluster_key: config
                .value("cluster.key")
                .filter(|s| !s.is_empty())?
                .to_string(),
            advertise_addr: config
                .property::<IpAddr>("cluster.advertise-addr")
                .unwrap_or(bind_addr),
            port: config
                .property_or_default::<u16>("cluster.bind-port", "1179")
                .unwrap_or(1179),
            ping_interval: config
                .property_or_default("cluster.heartbeat", "1s")
                .unwrap_or(Duration::from_secs(1)),
            peers: Vec::new(),
        };

        for (_, addr) in config.properties::<IpAddr>("cluster.seed-nodes") {
            if addr != builder.bind_addr && addr != builder.advertise_addr {
                builder.peers.push(Peer::new_seed(addr));
            }
        }

        builder.into()
    }

    pub async fn spawn(self, core: JmapInstance, mut shutdown_rx: watch::Receiver<bool>) {
        // Bind port
        let quidnunc = Arc::new(Quidnunc {
            socket: match UdpSocket::bind(SocketAddr::new(self.bind_addr, self.port)).await {
                Ok(socket) => socket,
                Err(e) => {
                    trc::event!(
                        Network(trc::NetworkEvent::BindError),
                        Details = "Failed to bind UDP socket",
                        LocalIp = self.bind_addr,
                        Reason = e.to_string()
                    );
                    return;
                }
            },
            nonce: b"428934328968".to_vec(),
            encryptor: SymmetricEncrypt::new(
                self.cluster_key.as_bytes(),
                "gossipmonger context key",
            ),
        });

        trc::event!(
            Network(trc::NetworkEvent::ListenStart),
            LocalIp = self.bind_addr,
            LocalPort = self.port,
            Protocol = trc::Protocol::Gossip,
        );

        // Create gossiper
        let (gossip_tx, mut gossip_rx) = mpsc::channel::<(SocketAddr, Request)>(IPC_CHANNEL_BUFFER);
        let mut gossiper = Gossiper {
            addr: self.advertise_addr,
            port: self.port,
            epoch: 0,
            peers: self.peers,
            last_peer_pinged: u32::MAX as usize,
            core,
            gossip_tx,
        };
        let quidnunc_ = quidnunc.clone();
        let bind_addr = self.bind_addr;
        let bind_port = self.port;

        // Spawn gossip sender
        tokio::spawn(async move {
            while let Some((target_addr, response)) = gossip_rx.recv().await {
                // Encrypt packets
                let mut bytes = response.to_bytes();
                match quidnunc_
                    .encryptor
                    .encrypt_in_place(&mut bytes, &quidnunc_.nonce)
                {
                    Ok(_) => {
                        if let Err(err) = quidnunc_.socket.send_to(&bytes, &target_addr).await {
                            trc::event!(
                                Network(trc::NetworkEvent::WriteError),
                                RemoteIp = target_addr.ip(),
                                RemotePort = target_addr.port(),
                                Protocol = trc::Protocol::Gossip,
                                Reason = err.to_string()
                            );
                        }
                    }
                    Err(err) => {
                        trc::event!(
                            Cluster(trc::ClusterEvent::Error),
                            RemoteIp = target_addr.ip(),
                            RemotePort = target_addr.port(),
                            Reason = err,
                            Details = "Failed to encrypt UDP packet"
                        );
                    }
                }
            }
        });

        // Spawn gossip listener
        let ping_interval = self.ping_interval;
        tokio::spawn(async move {
            let mut buf = vec![0; UDP_MAX_PAYLOAD];
            let mut last_ping = Instant::now();
            let mut wait = ping_interval;

            loop {
                tokio::select! {
                    packet = quidnunc.socket.recv_from(&mut buf) => {
                        match packet {
                            Ok((size, addr)) => {
                                // Decrypt packet
                                match quidnunc.encryptor.decrypt(&buf[..size], &quidnunc.nonce) {
                                    Ok(bytes) => {
                                        if let Some(request) = Request::from_bytes(&bytes) {
                                            //trc::event!("Received packet from {}", addr);
                                            match request {
                                                Request::Ping(peers) => {
                                                    gossiper.handle_ping(peers, true).await;
                                                },
                                                Request::Pong(peers) => {
                                                    gossiper.handle_ping(peers, false).await;
                                                },
                                                Request::Leave(peers) => {
                                                    gossiper.handle_leave(peers).await;
                                                },
                                            }
                                        } else {
                                            trc::event!(
                                                Cluster(trc::ClusterEvent::InvalidPacket),
                                                RemoteIp = addr.ip(),
                                                RemotePort = addr.port(),
                                                Contents = bytes,
                                            );
                                        }
                                    },
                                    Err(err) => {
                                        trc::event!(
                                            Cluster(trc::ClusterEvent::DecryptionError),
                                            RemoteIp = addr.ip(),
                                            RemotePort = addr.port(),
                                            Contents = (buf[..size]).to_vec(),
                                            Reason = err,
                                        );
                                    },
                                }
                            }
                            Err(err) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::ReadError),
                                    Protocol = trc::Protocol::Gossip,
                                    Reason = err.to_string()
                                );
                            }
                        }
                    },
                    _ = tokio::time::sleep(wait) => {
                        // Send ping
                        gossiper.ping_peers().await;
                        last_ping = Instant::now();
                    },
                    _ = shutdown_rx.changed() => {
                        trc::event!(
                            Network(trc::NetworkEvent::ListenStop),
                            LocalIp = bind_addr,
                            LocalPort = bind_port,
                            Protocol = trc::Protocol::Gossip,
                        );

                        // Broadcast leave message
                        gossiper.broadcast_leave().await;

                        break;
                    }
                };

                // Calculate next ping interval
                wait = ping_interval.saturating_sub(last_ping.elapsed());
            }
        });
    }
}
