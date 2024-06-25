/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

use common::manager::webadmin::Resource;
use directory::QueryBy;
use jmap_proto::error::request::RequestError;
use quick_xml::events::Event;
use quick_xml::Reader;
use utils::url_params::UrlParams;

use crate::{api::http::ToHttpResponse, JMAP};

use super::{HttpRequest, HttpResponse};

impl JMAP {
    pub async fn handle_autoconfig_request(&self, req: &HttpRequest) -> HttpResponse {
        // Obtain parameters
        let params = UrlParams::new(req.uri().query());
        let emailaddress = params
            .get("emailaddress")
            .unwrap_or_default()
            .to_lowercase();
        let (account_name, server_name, domain) =
            match self.autoconfig_parameters(&emailaddress).await {
                Ok(result) => result,
                Err(err) => return err.into_http_response(),
            };
        let services = match self.core.storage.config.get_services().await {
            Ok(services) => services,
            Err(err) => return err.into_http_response(),
        };

        // Build XML response
        let mut config = String::with_capacity(1024);
        config.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        config.push_str("<clientConfig version=\"1.1\">\n");
        let _ = writeln!(&mut config, "\t<emailProvider id=\"{domain}\">");
        let _ = writeln!(&mut config, "\t\t<domain>{domain}</domain>");
        let _ = writeln!(&mut config, "\t\t<displayName>{emailaddress}</displayName>");
        let _ = writeln!(
            &mut config,
            "\t\t<displayShortName>{domain}</displayShortName>"
        );
        for (protocol, port, is_tls) in services {
            let tag = match protocol.as_str() {
                "imap" | "pop3" => "incomingServer",
                "smtp" if port != 25 => "outgoingServer",
                _ => continue,
            };
            let _ = writeln!(&mut config, "\t\t<{tag} type=\"{protocol}\">");
            let _ = writeln!(&mut config, "\t\t\t<hostname>{server_name}</hostname>");
            let _ = writeln!(&mut config, "\t\t\t<port>{port}</port>");
            let _ = writeln!(
                &mut config,
                "\t\t\t<socketType>{}</socketType>",
                if is_tls { "SSL" } else { "STARTTLS" }
            );
            let _ = writeln!(&mut config, "\t\t\t<username>{account_name}</username>");
            let _ = writeln!(
                &mut config,
                "\t\t\t<authentication>password-cleartext</authentication>"
            );
            let _ = writeln!(&mut config, "\t\t</{tag}>");
        }

        config.push_str("\t</emailProvider>\n");
        let _ = writeln!(
            &mut config,
            "\t<clientConfigUpdate url=\"https://autoconfig.{domain}/mail/config-v1.1.xml\"></clientConfigUpdate>"
        );
        config.push_str("</clientConfig>\n");

        Resource {
            content_type: "application/xml; charset=utf-8",
            contents: config.into_bytes(),
        }
        .into_http_response()
    }

    pub async fn handle_autodiscover_request(&self, body: Option<Vec<u8>>) -> HttpResponse {
        // Obtain parameters
        let emailaddress = match parse_autodiscover_request(body.as_deref().unwrap_or_default()) {
            Ok(emailaddress) => emailaddress,
            Err(err) => {
                return RequestError::blank(400, "Failed to parse autodiscover request", err)
                    .into_http_response()
            }
        };
        let (account_name, server_name, _) = match self.autoconfig_parameters(&emailaddress).await {
            Ok(result) => result,
            Err(err) => return err.into_http_response(),
        };
        let services = match self.core.storage.config.get_services().await {
            Ok(services) => services,
            Err(err) => return err.into_http_response(),
        };

        // Build XML response
        let mut config = String::with_capacity(1024);
        let _ = writeln!(&mut config, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let _ = writeln!(&mut config, "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">");
        let _ = writeln!(&mut config, "\t<Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">");
        let _ = writeln!(&mut config, "\t\t<User>");
        let _ = writeln!(
            &mut config,
            "\t\t\t<DisplayName>{emailaddress}</DisplayName>"
        );
        let _ = writeln!(
            &mut config,
            "\t\t\t<AutoDiscoverSMTPAddress>{emailaddress}</AutoDiscoverSMTPAddress>"
        );
        // DeploymentId is a required field of User but we are not a MS Exchange server so use a random value
        let _ = writeln!(
            &mut config,
            "\t\t\t<DeploymentId>644560b8-a1ce-429c-8ace-23395843f701</DeploymentId>"
        );
        let _ = writeln!(&mut config, "\t\t</User>");
        let _ = writeln!(&mut config, "\t\t<Account>");
        let _ = writeln!(&mut config, "\t\t\t<AccountType>email</AccountType>");
        let _ = writeln!(&mut config, "\t\t\t<Action>settings</Action>");
        for (protocol, port, is_tls) in services {
            match protocol.as_str() {
                "imap" | "pop3" => (),
                "smtp" if port != 25 => (),
                _ => continue,
            }

            let _ = writeln!(&mut config, "\t\t\t<Protocol>");
            let _ = writeln!(
                &mut config,
                "\t\t\t\t<Type>{}</Type>",
                protocol.to_uppercase()
            );
            let _ = writeln!(&mut config, "\t\t\t\t<Server>{server_name}</Server>");
            let _ = writeln!(&mut config, "\t\t\t\t<Port>{port}</Port>");
            let _ = writeln!(&mut config, "\t\t\t\t<LoginName>{account_name}</LoginName>");
            let _ = writeln!(&mut config, "\t\t\t\t<AuthRequired>on</AuthRequired>");
            let _ = writeln!(&mut config, "\t\t\t\t<DirectoryPort>0</DirectoryPort>");
            let _ = writeln!(&mut config, "\t\t\t\t<ReferralPort>0</ReferralPort>");
            let _ = writeln!(
                &mut config,
                "\t\t\t\t<SSL>{}</SSL>",
                if is_tls { "on" } else { "off" }
            );
            if is_tls {
                let _ = writeln!(&mut config, "\t\t\t\t<Encryption>TLS</Encryption>");
            }
            let _ = writeln!(&mut config, "\t\t\t\t<SPA>off</SPA>");
            let _ = writeln!(&mut config, "\t\t\t</Protocol>");
        }

        let _ = writeln!(&mut config, "\t\t</Account>");
        let _ = writeln!(&mut config, "\t</Response>");
        let _ = writeln!(&mut config, "</Autodiscover>");

        Resource {
            content_type: "application/xml; charset=utf-8",
            contents: config.into_bytes(),
        }
        .into_http_response()
    }

    async fn autoconfig_parameters<'x>(
        &self,
        emailaddress: &'x str,
    ) -> Result<(String, String, &'x str), RequestError> {
        let domain = if let Some((_, domain)) = emailaddress.rsplit_once('@') {
            domain
        } else {
            return Err(RequestError::invalid_parameters());
        };

        // Obtain server name
        let server_name = if let Ok(Some(server_name)) = self
            .core
            .storage
            .config
            .get("lookup.default.hostname")
            .await
        {
            server_name
        } else {
            tracing::error!("Autoconfig request failed: Server name not configured");
            return Err(RequestError::internal_server_error());
        };

        // Find the account name by e-mail address
        let mut account_name = emailaddress.to_string();
        for id in self
            .core
            .storage
            .directory
            .email_to_ids(emailaddress)
            .await
            .unwrap_or_default()
        {
            if let Ok(Some(principal)) = self
                .core
                .storage
                .directory
                .query(QueryBy::Id(id), false)
                .await
            {
                account_name = principal.name;
                break;
            }
        }

        Ok((account_name, server_name, domain))
    }
}

fn parse_autodiscover_request(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("Empty request body".to_string());
    }

    let mut reader = Reader::from_reader(bytes);
    reader.trim_text(true);
    let mut buf = Vec::with_capacity(128);

    'outer: for tag_name in ["Autodiscover", "Request", "EMailAddress"] {
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let found_tag_name = e.name();
                    if tag_name
                        .as_bytes()
                        .eq_ignore_ascii_case(found_tag_name.as_ref())
                    {
                        continue 'outer;
                    } else if tag_name == "EMailAddress" {
                        // Skip unsupported tags under Request, such as AcceptableResponseSchema
                        let mut tag_count = 0;
                        loop {
                            match reader.read_event_into(&mut buf) {
                                Ok(Event::End(_)) => {
                                    if tag_count == 0 {
                                        break;
                                    } else {
                                        tag_count -= 1;
                                    }
                                }
                                Ok(Event::Start(_)) => {
                                    tag_count += 1;
                                }
                                Ok(Event::Eof) => {
                                    return Err(format!(
                                        "Expected value, found unexpected EOF at position {}.",
                                        reader.buffer_position()
                                    ))
                                }
                                _ => (),
                            }
                        }
                    } else {
                        return Err(format!(
                            "Expected tag {}, found unexpected tag {} at position {}.",
                            tag_name,
                            String::from_utf8_lossy(found_tag_name.as_ref()),
                            reader.buffer_position()
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "Error at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    ))
                }
                _ => {
                    return Err(format!(
                        "Expected tag {}, found unexpected EOF at position {}.",
                        tag_name,
                        reader.buffer_position()
                    ))
                }
            }
        }
    }

    if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
        if let Ok(text) = text.unescape() {
            if text.contains('@') {
                return Ok(text.trim().to_lowercase());
            }
        }
    }

    Err(format!(
        "Expected email address, found unexpected value at position {}.",
        reader.buffer_position()
    ))
}
