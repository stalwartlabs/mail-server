use std::net::IpAddr;

use crate::{Email, Hostname};

impl Hostname {
    pub fn new(host: &str) -> Self {
        let fqdn = host.to_lowercase();
        let ip = fqdn
            .strip_prefix('[')
            .and_then(|ip| ip.strip_suffix(']'))
            .unwrap_or(&fqdn)
            .parse::<IpAddr>()
            .ok();

        Hostname {
            ip,
            sld: if ip.is_none() {
                psl::domain_str(&fqdn).map(str::to_string)
            } else {
                None
            },
            fqdn,
        }
    }
}

impl Email {
    pub fn new(address: &str) -> Self {
        let address = address.to_lowercase();
        let (local_part, domain) = address.rsplit_once('@').unwrap_or_default();

        Email {
            local_part: local_part.to_string(),
            domain_part: Hostname::new(domain),
            address,
        }
    }
}
