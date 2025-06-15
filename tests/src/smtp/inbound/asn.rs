/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use common::{Core, Server, config::network::AsnGeoLookupConfig};

    #[tokio::test]
    #[ignore]
    async fn lookup_asn_country_dns() {
        let mut core = Core::default();
        core.network.asn_geo_lookup = AsnGeoLookupConfig::Dns {
            zone_ipv4: "origin.asn.cymru.com".to_string(),
            zone_ipv6: "origin6.asn.cymru.com".to_string(),
            separator: '|'.to_string(),
            index_asn: 0,
            index_asn_name: 3.into(),
            index_country: 2.into(),
        };
        let server = Server {
            core: core.into(),
            inner: Default::default(),
        };

        for (ip, asn, asn_name, country) in [
            ("8.8.8.8", 15169, "arin", "US"),
            ("1.1.1.1", 13335, "apnic", "AU"),
            ("2a01:4f9:c011:b43c::1", 24940, "ripencc", "DE"),
            ("1.33.1.1", 2514, "apnic", "JP"),
        ] {
            let result = server.lookup_asn_country(ip.parse().unwrap()).await;
            println!("{ip}: {result:?}");
            assert_eq!(result.asn.as_ref().map(|r| r.id), Some(asn));
            assert_eq!(
                result.asn.as_ref().and_then(|r| r.name.as_deref()),
                Some(asn_name)
            );
            assert_eq!(result.country.as_ref().map(|s| s.as_str()), Some(country));
        }
    }

    #[tokio::test]
    #[ignore]
    async fn lookup_asn_country_http() {
        let mut core = Core::default();
        core.network.asn_geo_lookup = AsnGeoLookupConfig::Resource {
            expires: Duration::from_secs(86400),
            timeout: Duration::from_secs(100),
            max_size: 100 * 1024 * 1024,
            headers: Default::default(),
            asn_resources: vec![
                //url: "file:///Users/me/code/playground/asn-ipv4.csv".to_string(),
                //url: "file:///Users/me/code/playground/asn-ipv6.csv".to_string(),
                "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv".to_string(),
                "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv6.csv".to_string(),
            ],
            geo_resources: vec![
                //url: "file:///Users/me/code/playground/geolite2-geo-whois-asn-country-ipv4.csv"
                //    .to_string(),
                //url: "file:///Users/me/code/playground/geolite2-geo-whois-asn-country-ipv6.csv"
                //    .to_string(),
                concat!(
                    "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-",
                    "asn-country/geolite2-geo-whois-asn-country-ipv4.csv"
                )
                .to_string(),
                concat!(
                    "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-",
                    "asn-country/geolite2-geo-whois-asn-country-ipv6.csv"
                )
                .to_string(),
            ],
        };
        let server = Server {
            core: core.into(),
            inner: Default::default(),
        };

        server.lookup_asn_country("8.8.8.8".parse().unwrap()).await;
        let time = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if server.inner.data.asn_geo_data.lock.available_permits() > 0 {
                break;
            }
        }
        println!("Fetch took {:?}", time.elapsed());

        for (ip, asn, asn_name, country) in [
            ("8.8.8.8", 15169, "Google LLC", "US"),
            ("1.1.1.1", 13335, "Cloudflare, Inc.", "AU"),
            ("2a01:4f9:c011:b43c::1", 24940, "Hetzner Online GmbH", "FI"),
            ("1.33.1.1", 2514, "NTT PC Communications, Inc.", "JP"),
        ] {
            let result = server.lookup_asn_country(ip.parse().unwrap()).await;
            println!("{ip}: {result:?}");
            assert_eq!(result.asn.as_ref().map(|r| r.id), Some(asn));
            assert_eq!(
                result.asn.as_ref().and_then(|r| r.name.as_deref()),
                Some(asn_name)
            );
            assert_eq!(result.country.as_ref().map(|s| s.as_str()), Some(country));
        }
    }
}
