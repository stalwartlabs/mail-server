use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use base64::{engine::general_purpose, Engine};
use dialoguer::{console::Term, theme::ColorfulTheme, Input, Select};
use openssl::rsa::Rsa;
use pwhash::sha512_crypt;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rusqlite::{Connection, OpenFlags};

const CFG_COMMON: &str = include_str!("../../../resources/config/common.toml");
const CFG_DIRECTORY: &str = include_str!("../../../resources/config/directory.toml");
const CFG_JMAP: &str = include_str!("../../../resources/config/jmap.toml");
const CFG_IMAP: &str = include_str!("../../../resources/config/imap.toml");
const CFG_SMTP: &str = include_str!("../../../resources/config/smtp.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    GCS,
    Azure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directory {
    SQL,
    LDAP,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpDirectory {
    SQL,
    LDAP,
    LMTP,
    IMAP,
}

const DIRECTORIES: [[&str; 2]; 6] = [
    ["bin", ""],
    ["etc", "dkim"],
    ["data", "blobs"],
    ["logs", ""],
    ["queue", ""],
    ["reports", ""],
];

fn main() -> std::io::Result<()> {
    let c = "fix";
    /*#[cfg(not(target_env = "msvc"))]
    unsafe {
        if libc::getuid() != 0 {
            eprintln!("This program must be run as root.");
            std::process::exit(1);
        }
    }*/

    println!("\nWelcome to the Stalwart mail server installer\n");

    let component = select::<Component>(
        "Which components would you like to install?",
        &[
            "All-in-one mail server (JMAP + IMAP + SMTP)",
            "JMAP server",
            "IMAP server",
            "SMTP server",
        ],
        Component::AllInOne,
    )?;
    let mut cfg_file = match component {
        Component::AllInOne | Component::Imap => {
            [CFG_COMMON, CFG_DIRECTORY, CFG_JMAP, CFG_IMAP, CFG_SMTP].join("\n")
        }
        Component::Jmap => [CFG_COMMON, CFG_DIRECTORY, CFG_JMAP, CFG_SMTP].join("\n"),
        Component::Smtp => [CFG_COMMON, CFG_DIRECTORY, CFG_SMTP].join("\n"),
    };
    let directory = if component != Component::Smtp {
        let backend = select::<Backend>(
            "Which database engine would you like to use?",
            &[
                "SQLite (single node, replicated with Litestream)",
                "FoundationDB (distributed and fault-tolerant)",
            ],
            Backend::SQLite,
        )?;
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
                    Directory::SQL | Directory::None => "sql",
                    Directory::LDAP => "ldap",
                },
            )
            .replace(
                "__SMTP_DIRECTORY__",
                match directory {
                    Directory::SQL | Directory::None => "sql",
                    Directory::LDAP => "ldap",
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
            SmtpDirectory::LMTP,
        )?;
        cfg_file = cfg_file
            .replace("__NEXT_HOP__", "lmtp")
            .replace(
                "__SMTP_DIRECTORY__",
                match smtp_directory {
                    SmtpDirectory::SQL => "sql",
                    SmtpDirectory::LDAP => "ldap",
                    SmtpDirectory::LMTP => "lmtp",
                    SmtpDirectory::IMAP => "imap",
                },
            )
            .replace(
                "__DIRECTORY__",
                match smtp_directory {
                    SmtpDirectory::SQL | SmtpDirectory::LMTP | SmtpDirectory::IMAP => "sql",
                    SmtpDirectory::LDAP => "ldap",
                },
            )
            .replace("__NEXT_HOP__", "lmtp");
        match smtp_directory {
            SmtpDirectory::SQL => Directory::SQL,
            SmtpDirectory::LDAP => Directory::LDAP,
            SmtpDirectory::LMTP | SmtpDirectory::IMAP => Directory::None,
        }
    };
    let base_path = PathBuf::from(input(
        "Installation directory",
        component.default_base_path(),
        dir_create_if_missing,
    )?);
    create_directories(&base_path)?;

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

    let cert_path = input(
        &format!("Where is the TLS certificate for '{hostname}' located?"),
        &format!("/etc/letsencrypt/live/{hostname}/fullchain.pem"),
        file_exists,
    )?;
    let pk_path = input(
        &format!("Where is the TLS private key for '{hostname}' located?"),
        &format!("/etc/letsencrypt/live/{hostname}/privkey.pem"),
        file_exists,
    )?;

    let dkim_instructions = generate_dkim(&base_path, &domain, &hostname)?;
    let admin_password = if matches!(directory, Directory::None) {
        create_auth_db(&base_path, &domain)?.into()
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
    fs::write(
        cfg_path,
        cfg_file
            .replace("__PATH__", base_path.to_str().unwrap())
            .replace("__DOMAIN__", &domain)
            .replace("__HOST__", &hostname)
            .replace("__CERT_PATH__", &cert_path)
            .replace("__PK_PATH__", &pk_path),
    )?;

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
        .interact_on_opt(&Term::stderr())?
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

fn create_auth_db(path: &Path, domain: &str) -> std::io::Result<String> {
    let mut path = PathBuf::from(path);
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
        "CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, secret TEXT, description TEXT, type TEXT NOT NULL, quota INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)".to_string(),
        "CREATE TABLE IF NOT EXISTS group_members (name TEXT NOT NULL, member_of TEXT NOT NULL, PRIMARY KEY (name, member_of))".to_string(),
        "CREATE TABLE IF NOT EXISTS emails (name TEXT NOT NULL, address TEXT NOT NULL, type TEXT, PRIMARY KEY (name, address))".to_string(),
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

#[cfg(not(target_env = "msvc"))]
unsafe fn get_uid_gid() -> (libc::uid_t, libc::gid_t) {
    use std::process::Command;
    let pw = libc::getpwnam("stalwart-mail".as_ptr() as *const i8);
    let gr = libc::getgrnam("stalwart-mail".as_ptr() as *const i8);

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
        let pw = libc::getpwnam("stalwart-mail".as_ptr() as *const i8);
        let gr = libc::getgrnam("stalwart-mail".as_ptr() as *const i8);
        (pw.as_ref().unwrap().pw_uid, gr.as_ref().unwrap().gr_gid)
    } else {
        ((*pw).pw_uid, ((*gr).gr_gid))
    }
}

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
            0 => Self::SQL,
            1 => Self::LDAP,
            2 => Self::None,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Self::SQL => 0,
            Self::LDAP => 1,
            Self::None => 2,
        }
    }
}

impl SelectItem for SmtpDirectory {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::SQL,
            1 => Self::LDAP,
            2 => Self::LMTP,
            3 => Self::IMAP,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            SmtpDirectory::SQL => 0,
            SmtpDirectory::LDAP => 1,
            SmtpDirectory::LMTP => 2,
            SmtpDirectory::IMAP => 3,
        }
    }
}

impl SelectItem for Blob {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Blob::Local,
            1 => Blob::MinIO,
            2 => Blob::S3,
            3 => Blob::GCS,
            4 => Blob::Azure,
            _ => unreachable!(),
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Blob::Local => 0,
            Blob::MinIO => 1,
            Blob::S3 => 2,
            Blob::GCS => 3,
            Blob::Azure => 4,
        }
    }
}

impl Component {
    fn default_base_path(&self) -> &'static str {
        match self {
            Self::AllInOne => "/opt/stalwart-mail",
            Self::Jmap => "/opt/stalwart-jmap",
            Self::Imap => "/opt/stalwart-imap",
            Self::Smtp => "/opt/stalwart-smtp",
        }
    }
}
