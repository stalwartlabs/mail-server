/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::imap::idle;

use super::ClusterTest;

pub async fn test(cluster: &ClusterTest) {
    println!("Running cluster broadcast tests...");

    // Run IMAP idle tests across nodes
    let mut node1_client = cluster.imap_client("john", 1).await;
    let mut node2_client = cluster.imap_client("john", 2).await;
    idle::test(&mut node1_client, &mut node2_client, true).await;

    // Test event broadcast
    let server1 = cluster.server(1);
    let server2 = cluster.server(2);
    let test_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!server1.is_ip_blocked(&test_ip));
    assert!(!server2.is_ip_blocked(&test_ip));
    server1.block_ip(test_ip).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(server1.is_ip_blocked(&test_ip));
    assert!(server2.is_ip_blocked(&test_ip));
}
