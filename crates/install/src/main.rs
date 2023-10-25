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
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    time::SystemTime,
};

use base64::{engine::general_purpose, Engine};
use clap::{Parser, ValueEnum};
use dialoguer::{console::Term, theme::ColorfulTheme, Input, Select};
use openssl::rsa::Rsa;
use pwhash::sha512_crypt;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rusqlite::{Connection, OpenFlags};

const CFG_COMMON: &str = "../../../resources/config/common.toml";
const CFG_DIRECTORY: &str = "../../../resources/config/directory_sql.toml";
const CFG_JMAP: &str = "../../../resources/config/jmap.toml";
const CFG_IMAP: &str = "../../../resources/config/imap.toml";
const CFG_SMTP: &str = "../../../resources/config/smtp.toml";

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
enum Backend {
    SQLite,
    FoundationDB,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blob {
    Local,
    MinIO,
    S3,
    Gcs,
    Azure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directory {
    Sql,
    Ldap,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpDirectory {
    Sql,
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

    // Build configuration file
    let mut cfg_file = match component {
        Component::AllInOne | Component::Imap => {
            [CFG_COMMON, CFG_DIRECTORY, CFG_JMAP, CFG_IMAP, CFG_SMTP].join("\n")
        }
        Component::Jmap => [CFG_COMMON, CFG_DIRECTORY, CFG_JMAP, CFG_SMTP].join("\n"),
        Component::Smtp => [CFG_COMMON, CFG_DIRECTORY, CFG_SMTP].join("\n"),
    };
    let mut download_url = None;

    // Obtain database engine
    let directory = if component != Component::Smtp {
        if !skip_download {
            let backend = select::<Backend>(
                "Which database engine would you like to use?",
                &[
                    "SQLite (single node, replicated with Litestream)",
                    "FoundationDB (distributed and fault-tolerant)",
                ],
                Backend::SQLite,
            )?;

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
                    Backend::SQLite => "sqlite",
                    Backend::FoundationDB => "foundationdb",
                },
                TARGET,
                PKG_EXTENSION
            )
            .into();
        }
        let blob = select::<Blob>(
            "Where would you like to store e-mails and blobs?",
            &[
                "Local disk using Maildir",
                "MinIO (or any S3-compatible object storage)",
                "Amazon S3",
                "Google Cloud Storage",
                "Azure Blob Storage",
            ],
            Blob::Local,
        )?;

        let directory = select::<Directory>(
            "Do you already have a directory or database containing your accounts?",
            &[
                "Yes, it's an SQL database",
                "Yes, it's an LDAP directory",
                "No, create a new directory for me",
            ],
            Directory::None,
        )?;
        cfg_file = cfg_file
            .replace(
                "__BLOB_STORE__",
                match blob {
                    Blob::Local => "local",
                    _ => "s3",
                },
            )
            .replace("__NEXT_HOP__", "local")
            .replace(
                "__DIRECTORY__",
                match directory {
                    Directory::Sql | Directory::None => "sql",
                    Directory::Ldap => "ldap",
                },
            )
            .replace(
                "__SMTP_DIRECTORY__",
                match directory {
                    Directory::Sql | Directory::None => "sql",
                    Directory::Ldap => "ldap",
                },
            )
            .replace(
                "__OAUTH_KEY__",
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(64)
                    .map(char::from)
                    .collect::<String>(),
            );

        directory
    } else {
        let smtp_directory = select::<SmtpDirectory>(
            "How should your local accounts be validated?",
            &[
                "SQL database",
                "LDAP directory",
                "LMTP server",
                "IMAP server",
            ],
            SmtpDirectory::Lmtp,
        )?;
        cfg_file = cfg_file
            .replace("__NEXT_HOP__", "lmtp")
            .replace(
                "__SMTP_DIRECTORY__",
                match smtp_directory {
                    SmtpDirectory::Sql => "sql",
                    SmtpDirectory::Ldap => "ldap",
                    SmtpDirectory::Lmtp => "lmtp",
                    SmtpDirectory::Imap => "imap",
                },
            )
            .replace(
                "__DIRECTORY__",
                match smtp_directory {
                    SmtpDirectory::Sql | SmtpDirectory::Lmtp | SmtpDirectory::Imap => "sql",
                    SmtpDirectory::Ldap => "ldap",
                },
            )
            .replace("__NEXT_HOP__", "lmtp");

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
        match smtp_directory {
            SmtpDirectory::Sql => Directory::Sql,
            SmtpDirectory::Ldap => Directory::Ldap,
            SmtpDirectory::Lmtp | SmtpDirectory::Imap => Directory::None,
        }
    };

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
            match reqwest::blocking::get(&url).and_then(|r| {
                if r.status().is_success() {
                    r.bytes().map(Ok)
                } else {
                    Ok(Err(r))
                }
            }) {
                Ok(Ok(bytes)) => {
                    let unpack_path = if !args.docker {
                        base_path.join("bin")
                    } else {
                        PathBuf::from("/usr/local/bin")
                    };

                    #[cfg(not(target_env = "msvc"))]
                    if let Err(err) =
                        tar::Archive::new(flate2::bufread::GzDecoder::new(Cursor::new(bytes)))
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
                Ok(Err(response)) => {
                    eprintln!(
                        "❌ Failed to download {}, make sure your platform is supported: {}",
                        url,
                        response.status()
                    );
                    return Ok(());
                }

                Err(err) => {
                    eprintln!("❌ Failed to download {}: {}", url, err);
                    return Ok(());
                }
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

    // Create authentication SQLite database
    let admin_password = if matches!(directory, Directory::None) {
        create_databases(&base_path, &domain)?.into()
    } else {
        None
    };

    // Write config file
    let cfg_path = base_path.join("etc").join("config.toml");
    if cfg_path.exists() {
        // Rename existing config file
        let backup_path = base_path.join("etc").join(format!(
            "config.toml.bak.{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ));
        fs::rename(&cfg_path, backup_path)?;
    }
    if args.docker {
        cfg_file = cfg_file
            .replace("127.0.0.1:8080", "0.0.0.0:8080")
            .replace("[server.run-as]", "#[server.run-as]")
            .replace("user = \"stalwart-mail\"", "#user = \"stalwart-mail\"")
            .replace("group = \"stalwart-mail\"", "#group = \"stalwart-mail\"");
    }
    fs::write(
        cfg_path,
        cfg_file
            .replace("__PATH__", base_path.to_str().unwrap())
            .replace("__DOMAIN__", &domain)
            .replace("__HOST__", &hostname)
            .replace("__CERT_PATH__", &cert_path)
            .replace("__PK_PATH__", &pk_path),
    )?;

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

    if let Some(admin_password) = admin_password {
        eprintln!("🔑 The administrator account is 'admin' with password '{admin_password}'.\n",);
    }

    Ok(())
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

fn create_databases(base_path: &Path, domain: &str) -> std::io::Result<String> {
    // Create accounts database
    let mut path = PathBuf::from(base_path);
    path.push("data");
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }
    path.push("accounts.sqlite3");

    let conn = Connection::open_with_flags(path, OpenFlags::default()).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to open database: {}", err),
        )
    })?;
    let secret = thread_rng()
        .sample_iter(Alphanumeric)
        .take(12)
        .map(char::from)
        .collect::<String>();
    let hashed_secret = sha512_crypt::hash(&secret).unwrap();
    for query in [
        concat!("CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, secret TEXT, description TEXT, ","type TEXT NOT NULL, quota INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)").to_string(),
        concat!("CREATE TABLE IF NOT EXISTS group_members (name TEXT NOT NULL, member_of ","TEXT NOT NULL, PRIMARY KEY (name, member_of))").to_string(),
        concat!("CREATE TABLE IF NOT EXISTS emails (name TEXT NOT NULL, address TEXT NOT NULL",", type TEXT, PRIMARY KEY (name, address))").to_string(),
        format!("INSERT OR REPLACE INTO accounts (name, secret, description, type) VALUES ('admin', '{hashed_secret}', 'Postmaster', 'individual')"), 
        format!("INSERT OR REPLACE INTO emails (name, address, type) VALUES ('admin', 'postmaster@{domain}', 'primary')"),
        "INSERT OR IGNORE INTO group_members (name, member_of) VALUES ('admin', 'superusers')".to_string()
    ] {
        conn.execute(&query, []).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create database: {}", err),
            )
        })?;
    }

    // Create Spam database
    let path = PathBuf::from(base_path)
        .join("data")
        .join("spamfilter.sqlite3");
    let conn = Connection::open_with_flags(path, OpenFlags::default()).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to open database: {}", err),
        )
    })?;
    for query in [
        concat!(
            "CREATE TABLE IF NOT EXISTS bayes_tokens (h1 INTEGER NOT NULL, ",
            "h2 INTEGER NOT NULL, ws INTEGER, wh INTEGER, PRIMARY KEY (h1, h2))",
        ),
        concat!(
            "CREATE TABLE IF NOT EXISTS seen_ids (id STRING NOT NULL PRIMARY KEY",
            ", ttl DATETIME NOT NULL)",
        ),
        concat!(
            "CREATE TABLE IF NOT EXISTS reputation (token STRING NOT NULL PRIMARY KEY",
            ", score FLOAT NOT NULL DEFAULT '0', count INT(11) NOT NULL ",
            "DEFAULT '0', ttl DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        ),
    ] {
        conn.execute(query, []).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create database: {}", err),
            )
        })?;
    }

    Ok(secret)
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

impl SelectItem for Backend {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::SQLite,
            1 => Self::FoundationDB,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Self::SQLite => 0,
            Self::FoundationDB => 1,
        }
    }
}

impl SelectItem for Directory {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Sql,
            1 => Self::Ldap,
            2 => Self::None,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Self::Sql => 0,
            Self::Ldap => 1,
            Self::None => 2,
        }
    }
}

impl SelectItem for SmtpDirectory {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Sql,
            1 => Self::Ldap,
            2 => Self::Lmtp,
            3 => Self::Imap,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            SmtpDirectory::Sql => 0,
            SmtpDirectory::Ldap => 1,
            SmtpDirectory::Lmtp => 2,
            SmtpDirectory::Imap => 3,
        }
    }
}

impl SelectItem for Blob {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Blob::Local,
            1 => Blob::MinIO,
            2 => Blob::S3,
            3 => Blob::Gcs,
            4 => Blob::Azure,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Blob::Local => 0,
            Blob::MinIO => 1,
            Blob::S3 => 2,
            Blob::Gcs => 3,
            Blob::Azure => 4,
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
