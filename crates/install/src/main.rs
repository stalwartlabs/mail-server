/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{
    fmt::{Display, Formatter},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::exit,
};

use base64::{engine::general_purpose, Engine};
use clap::{Parser, ValueEnum};
use dialoguer::{console::Term, theme::ColorfulTheme, Input, Select};
use openssl::rsa::Rsa;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

const CONFIG_URL: &str = "https://get.stalw.art/resources/config.zip";

#[cfg(target_os = "linux")]
const SERVICE: &str = include_str!("../../../resources/systemd/stalwart-mail.service");
#[cfg(target_os = "macos")]
const SERVICE: &str = include_str!("../../../resources/systemd/stalwart.mail.plist");

#[cfg(target_os = "linux")]
const ACCOUNT_NAME: &str = "stalwart-mail";
#[cfg(target_os = "macos")]
const ACCOUNT_NAME: &str = "_stalwart-mail";

#[cfg(not(target_env = "msvc"))]
const PKG_EXTENSION: &str = "tar.gz";

#[cfg(target_env = "msvc")]
const PKG_EXTENSION: &str = "zip";

static TARGET: &str = env!("TARGET");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Component {
    AllInOne,
    Jmap,
    Imap,
    Smtp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Store {
    RocksDB,
    FoundationDB,
    SQLite,
    PostgreSQL,
    MySQL,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blob {
    Internal,
    Filesystem,
    S3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fts {
    Internal,
    ElasticSearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpamDb {
    Internal,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directory {
    Internal,
    Ldap,
    PostgreSQL,
    MySQL,
    SQLite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpDirectory {
    PostgreSQL,
    MySQL,
    SQLite,
    Ldap,
    Lmtp,
    Imap,
}

const DIRECTORIES: [[&str; 2]; 6] = [
    ["bin", ""],
    ["etc", "dkim"],
    ["data", "blobs"],
    ["logs", ""],
    ["queue", ""],
    ["reports", ""],
];

#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
#[clap(name = "stalwart-cli")]
pub struct Arguments {
    #[clap(long, short = 'p')]
    path: Option<PathBuf>,
    #[clap(long, short = 'c')]
    component: Option<Component>,
    #[clap(long, short = 'd')]
    docker: bool,
}

fn main() -> std::io::Result<()> {
    let args = Arguments::parse();

    #[cfg(not(target_env = "msvc"))]
    unsafe {
        if libc::getuid() != 0 {
            eprintln!("This program must be run as root.");
            std::process::exit(1);
        }
    }

    println!("\nWelcome to the Stalwart Mail Server installer\n");

    // Obtain component to install
    let (component, skip_download) = if let Some(component) = args.component {
        (component, true)
    } else {
        (
            select::<Component>(
                "Which components would you like to install?",
                &[
                    "All-in-one mail server (JMAP + IMAP + SMTP)",
                    "JMAP server",
                    "IMAP server",
                    "SMTP server",
                ],
                Component::AllInOne,
            )?,
            false,
        )
    };

    // Obtain base path
    let base_path = if let Some(base_path) = args.path {
        base_path
    } else {
        PathBuf::from(input(
            "Installation directory",
            component.default_base_path(),
            dir_create_if_missing,
        )?)
    };
    create_directories(&base_path)?;

    // Download and unpack configuration files
    let cfg_path = base_path.join("etc");
    if let Err(err) = zip_extract::extract(Cursor::new(download(CONFIG_URL)), &cfg_path, true) {
        eprintln!(
            "❌ Failed to unpack configuration bundle {}: {}",
            CONFIG_URL, err
        );
        return Ok(());
    }

    // Build configuration file
    let mut download_url = None;

    // Obtain database engine
    if component != Component::Smtp {
        let backend = select::<Store>(
            "Which database would you like to use?",
            &[
                "RocksDB (recommended for single-node setups)",
                "FoundationDB (recommended for distributed environments)",
                "SQLite",
                "PostgreSQL",
                "MySQL",
            ],
            Store::RocksDB,
        )?;

        if !skip_download {
            download_url = format!(
                concat!(
                    "https://github.com/stalwartlabs/{}",
                    "/releases/latest/download/stalwart-{}-{}-{}.{}"
                ),
                match component {
                    Component::AllInOne => "mail-server",
                    Component::Jmap => "jmap-server",
                    Component::Imap => "imap-server",
                    Component::Smtp => unreachable!(),
                },
                match component {
                    Component::AllInOne => "mail",
                    Component::Jmap => "jmap",
                    Component::Imap => "imap",
                    Component::Smtp => unreachable!(),
                },
                match backend {
                    Store::FoundationDB => "distributed",
                    _ => "local",
                },
                TARGET,
                PKG_EXTENSION
            )
            .into();
        }
        let store = backend.to_string();
        let blob = select::<Blob>(
            "Where would you like to store e-mails and other large binaries?",
            &[
                &store,
                "Local file system",
                "S3, MinIO or any S3-compatible object storage",
            ],
            Blob::Internal,
        )?;

        let directory = select::<Directory>(
            "Do you already have a directory or database containing your user accounts?",
            &[
                &format!("No, I want Stalwart to manage my user accounts in {store}"),
                "Yes, it's an LDAP server",
                "Yes, it's an PostgreSQL database",
                "Yes, it's an MySQL database",
                "Yes, it's an SQLite database",
            ],
            Directory::Internal,
        )?;

        let fts = select::<Fts>(
            "Where would you like to store the full-text index?",
            &[&store, "ElasticSearch"],
            Fts::Internal,
        )?;

        let spamdb = select::<SpamDb>(
            "Where would you like to store the anti-spam database?",
            &[&store, "Redis"],
            SpamDb::Internal,
        )?;

        // Update settings
        sed(
            cfg_path.join("config.toml"),
            &[
                ("__STORE__", backend.id()),
                ("__DIRECTORY__", directory.id()),
            ],
        );
        sed(
            cfg_path.join("jmap").join("store.toml"),
            &[
                ("__BLOB_STORE__", blob.id().unwrap_or("%{DEFAULT_STORE}%")),
                ("__FTS_STORE__", fts.id().unwrap_or("%{DEFAULT_STORE}%")),
            ],
        );
        if let Some(id) = spamdb.id() {
            sed(
                cfg_path.join("common").join("sieve.toml"),
                &[("%{DEFAULT_STORE}%", id)],
            );
        }
        sed(
            cfg_path.join("jmap").join("oauth.toml"),
            &[(
                "__OAUTH_KEY__",
                thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(64)
                    .map(char::from)
                    .collect::<String>(),
            )],
        );

        // Enable stores
        for store in [
            backend.id().into(),
            blob.id(),
            fts.id(),
            spamdb.id(),
            directory.sql_store_id(),
        ]
        .into_iter()
        .flatten()
        {
            sed(
                cfg_path.join("store").join(format!("{store}.toml")),
                &[("disable = true", "disable = false")],
            );
        }

        // Enable directory
        if let Some(sql_id) = directory.sql_store_id() {
            sed(
                cfg_path.join("directory").join("sql.toml"),
                &[
                    ("disable = true", "disable = false"),
                    ("__SQL_STORE__", sql_id),
                ],
            );
        } else {
            sed(
                cfg_path
                    .join("directory")
                    .join(format!("{}.toml", directory.id())),
                &[("disable = true", "disable = false")],
            );
        }
    } else {
        let smtp_directory = select::<SmtpDirectory>(
            "How should your local accounts be validated?",
            &[
                "PostgreSQL database",
                "MySQL database",
                "SQLite database",
                "LDAP directory",
                "LMTP server",
                "IMAP server",
            ],
            SmtpDirectory::Lmtp,
        )?;

        let spamdb = select::<SpamDb>(
            "Where would you like to store the anti-spam database?",
            &["Local database", "Redis"],
            SpamDb::Internal,
        )?;

        // Update settings
        sed(
            cfg_path.join("config.toml"),
            &[
                ("__STORE__", "rocksdb"),
                ("__DIRECTORY__", smtp_directory.id()),
            ],
        );
        sed(
            cfg_path.join("jmap").join("store.toml"),
            &[
                ("__BLOB_STORE__", "%{DEFAULT_STORE}%"),
                ("__FTS_STORE__", "%{DEFAULT_STORE}%"),
            ],
        );
        if let Some(id) = spamdb.id() {
            sed(
                cfg_path.join("common").join("sieve.toml"),
                &[("%{DEFAULT_STORE}%", id)],
            );
        }

        // Enable directory
        if let Some(sql_id) = smtp_directory.sql_store_id() {
            sed(
                cfg_path.join("directory").join("sql.toml"),
                &[
                    ("disable = true", "disable = false"),
                    ("__SQL_STORE__", sql_id),
                ],
            );
        } else {
            sed(
                cfg_path
                    .join("directory")
                    .join(format!("{}.toml", smtp_directory.id())),
                &[("disable = true", "disable = false")],
            );
        }

        // Enable stores
        for store in [smtp_directory.sql_store_id(), spamdb.id(), "rocksdb".into()]
            .into_iter()
            .flatten()
        {
            sed(
                cfg_path.join("store").join(format!("{store}.toml")),
                &[("disable = true", "disable = false")],
            );
        }

        if !skip_download {
            download_url = format!(
                concat!(
                    "https://github.com/stalwartlabs/smtp-server",
                    "/releases/latest/download/stalwart-smtp-{}.{}"
                ),
                TARGET, PKG_EXTENSION
            )
            .into();
        }
    }

    // Download binary
    if let Some(download_url) = download_url {
        eprintln!("📦 Downloading components...");
        for url in [
            download_url,
            format!(
                concat!(
                    "https://github.com/stalwartlabs/mail-server",
                    "/releases/latest/download/stalwart-cli-{}.{}"
                ),
                TARGET, PKG_EXTENSION
            ),
        ] {
            let bytes = download(&url);
            let unpack_path = if !args.docker {
                base_path.join("bin")
            } else {
                PathBuf::from("/usr/local/bin")
            };

            #[cfg(not(target_env = "msvc"))]
            if let Err(err) = tar::Archive::new(flate2::bufread::GzDecoder::new(Cursor::new(bytes)))
                .unpack(unpack_path)
            {
                eprintln!("❌ Failed to unpack {}: {}", url, err);
                return Ok(());
            }

            #[cfg(target_env = "msvc")]
            if let Err(err) = zip_extract::extract(Cursor::new(bytes), &unpack_path, true) {
                eprintln!("❌ Failed to unpack {}: {}", url, err);
                return Ok(());
            }
        }
    }

    // Obtain domain name
    let domain = input(
        "What is your main domain name? (you can add others later)",
        "yourdomain.org",
        not_empty,
    )?
    .trim()
    .to_lowercase();
    let hostname = input(
        "What is your server hostname?",
        &format!("mail.{domain}"),
        not_empty,
    )?
    .trim()
    .to_lowercase();

    // Obtain TLS certificate path
    let (cert_path, pk_path) = if !args.docker {
        #[cfg(not(target_env = "msvc"))]
        let cert_base_path = format!("/etc/letsencrypt/live/{}/", hostname);
        #[cfg(target_env = "msvc")]
        let cert_base_path = format!("C:\\Program Files\\Letsencrypt\\live\\{}\\", hostname);

        (
            input(
                &format!("Where is the TLS certificate for '{hostname}' located?"),
                &format!("{cert_base_path}fullchain.pem"),
                file_exists,
            )?,
            input(
                &format!("Where is the TLS private key for '{hostname}' located?"),
                &format!("{cert_base_path}privkey.pem"),
                file_exists,
            )?,
        )
    } else {
        // Create directories
        fs::create_dir_all(base_path.join("etc").join("certs").join(&hostname))?;
        (
            format!(
                "{}/etc/certs/{}/fullchain.pem",
                base_path.display(),
                hostname
            ),
            format!("{}/etc/certs/{}/privkey.pem", base_path.display(), hostname),
        )
    };

    // Generate DKIM key and instructions
    let dkim_instructions = generate_dkim(&base_path, &domain, &hostname)?;

    // Update config file
    if args.docker {
        sed(
            cfg_path.join("common").join("server.toml"),
            &[
                ("[server.run-as]", "#[server.run-as]"),
                ("user = \"stalwart-mail\"", "#user = \"stalwart-mail\""),
                ("group = \"stalwart-mail\"", "#group = \"stalwart-mail\""),
            ],
        );
        sed(
            cfg_path.join("smtp").join("listener.toml"),
            &[("127.0.0.1:8080", "[::]:8080")],
        );
    }
    sed(
        cfg_path.join("config.toml"),
        &[
            ("__BASE_PATH__", base_path.to_str().unwrap()),
            ("__DOMAIN__", &domain),
            ("__HOST__", &hostname),
        ],
    );
    sed(
        cfg_path.join("common").join("tls.toml"),
        &[("__CERT_PATH__", &cert_path), ("__PK_PATH__", &pk_path)],
    );

    // Write service file

    if !args.docker {
        // Change permissions
        #[cfg(not(target_env = "msvc"))]
        {
            let mut cmd = std::process::Command::new("chown");
            cmd.arg("-R")
                .arg(format!("{}:{}", ACCOUNT_NAME, ACCOUNT_NAME))
                .arg(&base_path);
            if let Err(err) = cmd.status() {
                eprintln!("Warning: Failed to set permissions: {}", err);
            }
            let mut cmd = std::process::Command::new("chmod");
            cmd.arg("-R")
                .arg("770")
                .arg(&format!("{}/etc", base_path.display()))
                .arg(&format!("{}/data", base_path.display()))
                .arg(&format!("{}/queue", base_path.display()))
                .arg(&format!("{}/reports", base_path.display()))
                .arg(&format!("{}/logs", base_path.display()));
            if let Err(err) = cmd.status() {
                eprintln!("Warning: Failed to set permissions: {}", err);
            }
        }

        #[cfg(target_os = "linux")]
        {
            let service_file = format!(
                "/etc/systemd/system/stalwart-{}.service",
                component.binary_name()
            );
            let service_name = format!("stalwart-{}", component.binary_name());
            match fs::write(
                &service_file,
                SERVICE
                    .replace("__PATH__", base_path.to_str().unwrap())
                    .replace("__NAME__", component.binary_name())
                    .replace("__TITLE__", component.name()),
            ) {
                Ok(_) => {
                    if let Err(err) = std::process::Command::new("/bin/systemctl")
                        .arg("enable")
                        .arg(service_file)
                        .status()
                        .and_then(|_| {
                            std::process::Command::new("/bin/systemctl")
                                .arg("restart")
                                .arg(&service_name)
                                .status()
                        })
                    {
                        eprintln!("Warning: Failed to start service: {}", err);
                    }
                }
                Err(err) => {
                    eprintln!("Warning: Failed to write service file: {}", err);
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let service_file = format!(
                "/Library/LaunchDaemons/stalwart.{}.plist",
                component.binary_name()
            );
            let service_name = format!("system/stalwart.{}", component.binary_name());
            match fs::write(
                &service_file,
                SERVICE
                    .replace("__PATH__", base_path.to_str().unwrap())
                    .replace("__NAME__", component.binary_name())
                    .replace("__TITLE__", component.name()),
            ) {
                Ok(_) => {
                    if let Err(err) = std::process::Command::new("launchctl")
                        .arg("load")
                        .arg(service_file)
                        .status()
                        .and_then(|_| {
                            std::process::Command::new("launchctl")
                                .arg("enable")
                                .arg(&service_name)
                                .status()
                        })
                        .and_then(|_| {
                            std::process::Command::new("launchctl")
                                .arg("start")
                                .arg(&service_name)
                                .status()
                        })
                    {
                        eprintln!("Warning: Failed to start service: {}", err);
                    }
                }
                Err(err) => {
                    eprintln!("Warning: Failed to write service file: {}", err);
                }
            }
        }
    }

    eprintln!("\n🎉 Installation completed!\n\n✅ {dkim_instructions}\n");

    Ok(())
}

fn sed(path: impl AsRef<Path>, replacements: &[(&str, impl AsRef<str>)]) {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(mut contents) => {
            for (from, to) in replacements {
                contents = contents.replace(from, to.as_ref());
            }
            if let Err(err) = fs::write(path, contents) {
                eprintln!(
                    "❌ Failed to write configuration file {}: {}",
                    path.display(),
                    err
                );
                exit(1);
            }
        }
        Err(err) => {
            eprintln!(
                "❌ Failed to read configuration file {}: {}",
                path.display(),
                err
            );
            exit(1);
        }
    }
}

fn download(url: &str) -> Vec<u8> {
    match reqwest::blocking::get(url).and_then(|r| {
        if r.status().is_success() {
            r.bytes().map(Ok)
        } else {
            Ok(Err(r))
        }
    }) {
        Ok(Ok(bytes)) => bytes.to_vec(),
        Ok(Err(response)) => {
            eprintln!(
                "❌ Failed to download {}, make sure your platform is supported: {}",
                url,
                response.status()
            );
            exit(1);
        }

        Err(err) => {
            eprintln!("❌ Failed to download {}: {}", url, err);
            exit(1);
        }
    }
}

fn select<T: SelectItem>(prompt: &str, items: &[&str], default: T) -> std::io::Result<T> {
    if let Some(index) = Select::with_theme(&ColorfulTheme::default())
        .items(items)
        .with_prompt(prompt)
        .default(default.to_index())
        .interact_on_opt(&Term::stderr())
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read input: {}", err),
            )
        })?
    {
        Ok(T::from_index(index))
    } else {
        eprintln!("Aborted.");
        std::process::exit(1);
    }
}

fn input(
    prompt: &str,
    default: &str,
    validator: fn(&String) -> Result<(), String>,
) -> std::io::Result<String> {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default.to_string())
        .validate_with(validator)
        .interact_text_on(&Term::stderr())
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read input: {}", err),
            )
        })
}

fn dir_create_if_missing(path: &String) -> Result<(), String> {
    let path = Path::new(path);
    if path.is_dir() {
        Ok(())
    } else if let Err(e) = std::fs::create_dir_all(path) {
        Err(format!(
            "Failed to create directory {}: {}",
            path.display(),
            e
        ))
    } else {
        Ok(())
    }
}

fn file_exists(path: &String) -> Result<(), String> {
    let path = Path::new(path);
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("File {} does not exist", path.display()))
    }
}

#[allow(clippy::ptr_arg)]
fn not_empty(value: &String) -> Result<(), String> {
    if value.trim().is_empty() {
        Err("Value cannot be empty".to_string())
    } else {
        Ok(())
    }
}

fn create_directories(path: &Path) -> std::io::Result<()> {
    for dir in &DIRECTORIES {
        let mut path = PathBuf::from(path);
        path.push(dir[0]);
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        if !dir[1].is_empty() {
            path.push(dir[1]);
            if !path.exists() {
                fs::create_dir_all(&path)?;
            }
        }
    }

    Ok(())
}

fn generate_dkim(path: &Path, domain: &str, hostname: &str) -> std::io::Result<String> {
    let mut path = PathBuf::from(path);
    path.push("etc");
    path.push("dkim");
    fs::create_dir_all(&path)?;

    // Generate key
    let rsa = Rsa::generate(2048)?;
    let mut public = String::new();
    general_purpose::STANDARD.encode_string(rsa.public_key_to_der()?, &mut public);
    let private = rsa.private_key_to_pem()?;

    // Write private key
    let mut pk_path = path.clone();
    pk_path.push(&format!("{domain}.key"));
    fs::write(pk_path, private)?;

    // Write public key
    let mut pub_path = path.clone();
    pub_path.push(&format!("{domain}.cert"));
    fs::write(pub_path, public.as_bytes())?;

    // Write instructions
    let instructions = format!(
        "Add the following DNS records to your domain in order to enable DKIM, SPF and DMARC:\n\
         \n\
         stalwart._domainkey.{domain}. IN TXT \"v=DKIM1; k=rsa; p={public}\"\n\
         {domain}. IN TXT \"v=spf1 a:{hostname} mx -all ra=postmaster\"\n\
         {hostname}. IN TXT \"v=spf1 a -all ra=postmaster\"\n\
         _dmarc.{domain}. IN TXT \"v=DMARC1; p=none; rua=mailto:postmaster@{domain}; ruf=mailto:postmaster@{domain}\"\n\
         ",
    );
    let mut txt_path = path.clone();
    txt_path.push(&format!("{domain}.readme"));
    fs::write(txt_path, instructions.as_bytes())?;

    Ok(instructions)
}

/*#[cfg(not(target_env = "msvc"))]
unsafe fn get_uid_gid() -> (libc::uid_t, libc::gid_t) {
    use std::{ffi::CString, process::Command};
    let c_str = CString::new("stalwart-mail").unwrap();
    let pw = libc::getpwnam(c_str.as_ptr());
    let gr = libc::getgrnam(c_str.as_ptr());

    if pw.is_null() || gr.is_null() {
        let mut cmd = Command::new("useradd");
        cmd.arg("-r")
            .arg("-s")
            .arg("/sbin/nologin")
            .arg("-M")
            .arg("stalwart-mail");
        if let Err(e) = cmd.status() {
            eprintln!("Failed to create stalwart system account: {}", e);
            std::process::exit(1);
        }
        let pw = libc::getpwnam(c_str.as_ptr());
        let gr = libc::getgrnam(c_str.as_ptr());
        (pw.as_ref().unwrap().pw_uid, gr.as_ref().unwrap().gr_gid)
    } else {
        ((*pw).pw_uid, ((*gr).gr_gid))
    }
}*/

trait SelectItem {
    fn from_index(index: usize) -> Self;
    fn to_index(&self) -> usize;
}

impl SelectItem for Component {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::AllInOne,
            1 => Self::Jmap,
            2 => Self::Imap,
            3 => Self::Smtp,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Self::AllInOne => 0,
            Self::Jmap => 1,
            Self::Imap => 2,
            Self::Smtp => 3,
        }
    }
}

impl SelectItem for Store {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::RocksDB,
            1 => Self::FoundationDB,
            2 => Self::SQLite,
            3 => Self::PostgreSQL,
            4 => Self::MySQL,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Store::RocksDB => 0,
            Store::FoundationDB => 1,
            Store::SQLite => 2,
            Store::PostgreSQL => 3,
            Store::MySQL => 4,
        }
    }
}

impl SelectItem for Directory {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Internal,
            1 => Self::Ldap,
            2 => Self::PostgreSQL,
            3 => Self::MySQL,
            4 => Self::SQLite,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Directory::Internal => 0,
            Directory::Ldap => 1,
            Directory::PostgreSQL => 2,
            Directory::MySQL => 3,
            Directory::SQLite => 4,
        }
    }
}

impl SelectItem for SmtpDirectory {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::PostgreSQL,
            1 => Self::MySQL,
            2 => Self::SQLite,
            3 => Self::Ldap,
            4 => Self::Lmtp,
            5 => Self::Imap,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            SmtpDirectory::PostgreSQL => 0,
            SmtpDirectory::MySQL => 1,
            SmtpDirectory::SQLite => 2,
            SmtpDirectory::Ldap => 3,
            SmtpDirectory::Lmtp => 4,
            SmtpDirectory::Imap => 5,
        }
    }
}

impl SelectItem for Blob {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Internal,
            1 => Self::Filesystem,
            2 => Self::S3,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Blob::Internal => 0,
            Blob::Filesystem => 1,
            Blob::S3 => 2,
        }
    }
}

impl SelectItem for SpamDb {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Internal,
            1 => Self::Redis,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            SpamDb::Internal => 0,
            SpamDb::Redis => 1,
        }
    }
}

impl SelectItem for Fts {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Internal,
            1 => Self::ElasticSearch,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Fts::Internal => 0,
            Fts::ElasticSearch => 1,
        }
    }
}

impl Component {
    fn default_base_path(&self) -> &'static str {
        #[cfg(not(target_env = "msvc"))]
        match self {
            Self::AllInOne => "/opt/stalwart-mail",
            Self::Jmap => "/opt/stalwart-jmap",
            Self::Imap => "/opt/stalwart-imap",
            Self::Smtp => "/opt/stalwart-smtp",
        }
        #[cfg(target_env = "msvc")]
        match self {
            Self::AllInOne => "C:\\Program Files\\Stalwart Mail",
            Self::Jmap => "C:\\Program Files\\Stalwart JMAP",
            Self::Imap => "C:\\Program Files\\Stalwart IMAP",
            Self::Smtp => "C:\\Program Files\\Stalwart SMTP",
        }
    }

    fn binary_name(&self) -> &'static str {
        match self {
            Self::AllInOne => "mail",
            Self::Jmap => "jmap",
            Self::Imap => "imap",
            Self::Smtp => "smtp",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::AllInOne => "Mail",
            Self::Jmap => "JMAP",
            Self::Imap => "IMAP",
            Self::Smtp => "SMTP",
        }
    }
}

impl Display for Store {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RocksDB => write!(f, "RocksDB"),
            Self::FoundationDB => write!(f, "FoundationDB"),
            Self::SQLite => write!(f, "SQLite"),
            Self::PostgreSQL => write!(f, "PostgreSQL"),
            Self::MySQL => write!(f, "MySQL"),
        }
    }
}

impl Store {
    pub fn id(&self) -> &'static str {
        match self {
            Self::RocksDB => "rocksdb",
            Self::FoundationDB => "foundationdb",
            Self::SQLite => "sqlite",
            Self::PostgreSQL => "postgresql",
            Self::MySQL => "mysql",
        }
    }
}

impl Directory {
    pub fn id(&self) -> &'static str {
        match self {
            Directory::Internal => "internal",
            Directory::Ldap => "ldap",
            Directory::PostgreSQL | Directory::MySQL | Directory::SQLite => "sql",
        }
    }

    pub fn sql_store_id(&self) -> Option<&'static str> {
        match self {
            Directory::PostgreSQL => Some("postgresql"),
            Directory::MySQL => Some("mysql"),
            Directory::SQLite => Some("sqlite"),
            Directory::Internal | Directory::Ldap => None,
        }
    }
}

impl SmtpDirectory {
    pub fn id(&self) -> &'static str {
        match self {
            SmtpDirectory::Ldap => "ldap",
            SmtpDirectory::Lmtp => "lmtp",
            SmtpDirectory::Imap => "imap",
            SmtpDirectory::PostgreSQL | SmtpDirectory::MySQL | SmtpDirectory::SQLite => "sql",
        }
    }

    pub fn sql_store_id(&self) -> Option<&'static str> {
        match self {
            SmtpDirectory::PostgreSQL => Some("postgresql"),
            SmtpDirectory::MySQL => Some("mysql"),
            SmtpDirectory::SQLite => Some("sqlite"),
            SmtpDirectory::Ldap | SmtpDirectory::Lmtp | SmtpDirectory::Imap => None,
        }
    }
}

impl Blob {
    pub fn id(&self) -> Option<&'static str> {
        match self {
            Self::Internal => None,
            Self::Filesystem => "fs".into(),
            Self::S3 => "s3".into(),
        }
    }
}

impl Fts {
    pub fn id(&self) -> Option<&'static str> {
        match self {
            Self::Internal => None,
            Self::ElasticSearch => "elasticsearch".into(),
        }
    }
}

impl SpamDb {
    pub fn id(&self) -> Option<&'static str> {
        match self {
            Self::Internal => None,
            Self::Redis => "redis".into(),
        }
    }
}
