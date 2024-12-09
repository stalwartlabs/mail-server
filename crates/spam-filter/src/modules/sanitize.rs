use std::net::IpAddr;

use crate::{Email, Hostname};

impl Hostname {
    pub fn new(host: &str) -> Self {
        let mut fqdn = host.to_lowercase();

        // Decode punycode
        if fqdn.contains("xn--") {
            let mut decoded = String::with_capacity(fqdn.len());

            for part in fqdn.split('.') {
                if !decoded.is_empty() {
                    decoded.push('.');
                }

                if let Some(puny) = part
                    .strip_prefix("xn--")
                    .and_then(idna::punycode::decode_to_string)
                {
                    decoded.push_str(&puny);
                } else {
                    decoded.push_str(part);
                }
            }

            fqdn = decoded;
        }

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

impl Hostname {
    pub fn sld_or_default(&self) -> &str {
        self.sld.as_deref().unwrap_or(self.fqdn.as_str())
    }
}
