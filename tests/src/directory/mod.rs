/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod imap;
pub mod internal;
pub mod ldap;
pub mod smtp;
pub mod sql;

use common::{config::smtp::session::AddressMapping, Core};
use directory::{backend::internal::manage::ManageDirectory, Directories};
use mail_send::Credentials;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::PrivateKeyDer;
use std::{borrow::Cow, io::BufReader, sync::Arc};
use store::{LookupStore, Store, Stores};
use tokio_rustls::TlsAcceptor;

use crate::{store::TempDir, AssertConfig};

const CONFIG: &str = r#"
[directory."rocksdb"]
type = "internal"
store = "rocksdb"

[directory."foundationdb"]
type = "internal"
store = "foundationdb"

[directory."sqlite"]
type = "sql"
store = "sqlite"

[directory."sqlite".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
class = "type"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/rocksdb"

[store."foundationdb"]
type = "foundationdb"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/auth.db"

[store."sqlite".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ? ORDER BY name ASC"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"

[storage]
lookup = "sqlite"

##############################################################################

[directory."postgresql"]
type = "sql"
store = "postgresql"

[directory."postgresql".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
class = "type"

[store."postgresql"]
type = "postgresql"
host = "localhost"
port = 5432
database = "stalwart"
user = "postgres"
password = "mysecretpassword"

[store."postgresql".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = $1 AND active = true"
members = "SELECT member_of FROM group_members WHERE name = $1"
recipients = "SELECT name FROM emails WHERE address = $1 ORDER BY name ASC"
emails = "SELECT address FROM emails WHERE name = $1 AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || $1 || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = $1 AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || $1 LIMIT 1"

##############################################################################

[directory."mysql"]
type = "sql"
store = "mysql"

[directory."mysql".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
class = "type"

[store."mysql"]
type = "mysql"
host = "localhost"
port = 3307
database = "stalwart"
user = "root"
password = "password"

[store."mysql".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ? ORDER BY name ASC"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE CONCAT('%', ?, '%') AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE CONCAT('%@', ?) LIMIT 1"

##############################################################################

[directory."ldap"]
type = "ldap"
url = "ldap://localhost:3893"
base-dn = "dc=example,dc=org"

[directory."ldap".bind]
dn = "cn=serviceuser,ou=svcaccts,dc=example,dc=org"
secret = "mysecret"

[directory."ldap".bind.auth]
enable = false
dn = "cn=?,ou=svcaccts,dc=example,dc=org"

[directory."ldap".filter]
name = "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(uid=?))"
email = "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(|(mail=?)(givenName=?)(sn=?)))"
verify = "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(|(mail=*?*)(givenName=*?*)))"
expand = "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(sn=?))"
domains = "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(|(mail=*@?)(givenName=*@?)(sn=*@?)))"

# Glauth does not support searchable custom attributes so
# 'sn' and 'givenName' are used to search for aliases/lists.

[directory."ldap".attributes]
name = "uid"
description = ["principalName", "description"]
secret = "userPassword"
groups = ["memberOf", "otherGroups"]
email = "mail"
email-alias = "givenName"
quota = "diskQuota"
class = "objectClass"

##############################################################################

[directory."imap"]
type = "imap"
host = "127.0.0.1"
port = 9198

[directory."imap".pool]
max-connections = 5

[directory."imap".tls]
enable = true
allow-invalid-certs = true

##############################################################################

[directory."smtp"]
type = "lmtp"
host = "127.0.0.1"
port = 9199

[directory."smtp".limits]
auth-errors = 3
rcpt = 5

[directory."smtp".pool]
max-connections = 5

[directory."smtp".tls]
enable = true
allow-invalid-certs = true

[directory."smtp".cache]
entries = 500
ttl = {positive = '10s', negative = '5s'}

##############################################################################

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
class = "individual"
description = "John Doe"
secret = "12345"
email = ["john@example.org", "jdoe@example.org", "john.doe@example.org"]
email-list = ["info@example.org"]
member-of = ["sales"]

[[directory."local".principals]]
name = "jane"
class = "individual"
description = "Jane Doe"
secret = "abcde"
email = "jane@example.org"
email-list = ["info@example.org"]
member-of = ["sales", "support"]

[[directory."local".principals]]
name = "bill"
class = "individual"
description = "Bill Foobar"
secret = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"
quota = 500000
email = "bill@example.org"
email-list = ["info@example.org"]

[[directory."local".principals]]
name = "sales"
class = "group"
description = "Sales Team"

[[directory."local".principals]]
name = "support"
class = "group"
description = "Support Team"

"#;

pub struct DirectoryStore {
    pub store: LookupStore,
}

pub struct DirectoryTest {
    pub directories: Directories,
    pub stores: Stores,
    pub temp_dir: TempDir,
    pub core: Core,
}

impl DirectoryTest {
    pub async fn new(id_store: Option<&str>) -> DirectoryTest {
        let temp_dir = TempDir::new("directory_tests", true);
        let mut config_file = CONFIG.replace("{TMP}", &temp_dir.path.to_string_lossy());
        if id_store.is_some() {
            // Disable foundationdb store for SQL tests (the fdb select api version can only be run once per process)
            config_file = config_file
                .replace(
                    "type = \"foundationdb\"",
                    "type = \"foundationdb\"\ndisable = true",
                )
                .replace(
                    "store = \"foundationdb\"",
                    "store = \"foundationdb\"\ndisable = true",
                )
        } else {
            // Disable internal store
            config_file =
                config_file.replace("type = \"memory\"", "type = \"memory\"\ndisable = true")
        }
        let mut config = utils::config::Config::new(&config_file).unwrap();
        let stores = Stores::parse_all(&mut config).await;
        let directories = Directories::parse(
            &mut config,
            &stores,
            id_store
                .map(|id| stores.stores.get(id).unwrap().clone())
                .unwrap_or_default(),
        )
        .await;
        config.assert_no_errors();

        // Enable catch-all and subaddressing
        let mut core = Core::default();
        core.smtp.session.rcpt.catch_all = AddressMapping::Enable;
        core.smtp.session.rcpt.subaddressing = AddressMapping::Enable;

        DirectoryTest {
            directories,
            stores,
            temp_dir,
            core,
        }
    }
}

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUCgHGQYUqtelbHGVSzCVwBL3fyEUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIyMDUxNjExNDAzNFoXDTIzMDUx
NjExNDAzNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAtwS0Fzl3SjaCuKEXgZ/fdWbDoj/qDphyNCAKNevQ0+D0
STNkWCO04aFSH0zcL8zoD9gokNos0i7OU9//ZhZQmex4V6EFdZn8bFwUWN/scUvW
HEFXVjtHldO2isZgIxH9LuwRv7KAgkISuWahqerOVDhe7SeQUV0AJGNEh3cT9PZr
gSY931BxB7n+5k8eoSk8Z1gtBzQzL62kVGpHDKfw8yX8m65owF9eLUBrNzgxmXfC
xpuHwj7hmVhS09PPKeN/RsFS8PsYO7bo0u8jEKalteumjRT7RyUEbioqfo6ZFOGj
FHPIq/uKXS9zN1fpoyNh3ur5hMznQhrqlwBM9KlM7GdBJ0pZ3ad0YjT8IL/GnGKR
85J2WZdLqaQdUZo7nV67FhqdDlNE4MdwiykTMjfmLRXGAVhAzJHKyRKNwmkI2aqe
S7aqeNgvuDBwY80Q9a2rb5py1Aw+L8yCkUBuHboToDpxSVRDNN8DrWNmmsXnxsOG
wRDODy4GICKyxlP+RFSM8xWSQ6y9ktS2OfDBm+Eqcw+3pZKhdz2wgxLkUBJ8X1eh
kJrCA/6LTuhy6m6mMjAfoSOFU7fu88jxaWPgvP7GKyH+LM/t9eucobz2ks5rtSjz
V4Dc5DCS94/OpVRHwHdaFSPbJKBN9Ev8gnNrAyx/aBPGoHBPG/QUiU7dcUNIPt0C
AwEAAaNTMFEwHQYDVR0OBBYEFI167IxBmErB11EqiPPqFLa31ZaMMB8GA1UdIwQY
MBaAFI167IxBmErB11EqiPPqFLa31ZaMMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggIBALU00IOiH5ubEauVCmakms5ermNTZfculnhnDfWTLMeh2+a7
G4cqADErfMhm/mmLbrw33t9s6tCAhQltvewKR40ST9uMPSyiQbYaCXd5DXnuI6Ox
JtNW+UOWIaMf8abnkdLvREOvb8dVQS1i3xq14tAjY5XgpGwCPP8m54b7N3Q7soLn
e5PDhPNTnhRIn2RLuYoZmQmMA5fcqEUDYff4epUww7PhrM1QckZligI3566NlGOf
j1G9JrivBtY0eaJtamIFnGMBT0ThDudxVja2Nv0C2Elry0p4T/o4nc4M67BJ/y1R
vjNLAgFhbxssemU3lZqSd+pykpJBwDBjFSPrZZmQcbk7H6Uz8V1xr/xuzfw6fA13
NWZ5vLgP/DQ13sM+XFlxThKfbPMPVe/UCTvfGtNW+3XyBgPntEkR+fNEawQmzbYl
R+X1ymT9MZnEZqRMf7/UD/SYek1aUJefoew3upjMgxYVvh4F8dqJ+39F+xoFzIA2
1dDAEMzXtjA3zKhZ2cycZbEzpJvYA3eGLuR16Suqfi4kPvfwK0mOhCxQmpayt7/X
vuEzW6dPCH8Hgbb0WvsSppGOvhdbDaZFNfFc5eNSxhyKzu3H3ACNImZRtZE+yixx
0fR8+xz9kDLf8xupV+X9heyFGHSyYU2Lveaevtr2Ij3weLRgJ6LbNALoeKXk
-----END CERTIFICATE-----
";
const PK: &str = "-----BEGIN PRIVATE KEY-----
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
XzVV5pwOxkIDBWDIqMUfwJDChBKfpw==
-----END PRIVATE KEY-----
";

pub fn dummy_tls_acceptor() -> Arc<TlsAcceptor> {
    // Init server config builder with safe defaults
    let config = ServerConfig::builder().with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(CERT.as_bytes());
    let key_file = &mut BufReader::new(PK.as_bytes());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file).map(|r| r.unwrap()).collect();
    let mut keys: Vec<PrivateKeyDer> = pkcs8_private_keys(key_file)
        .map(|v| PrivateKeyDer::Pkcs8(v.unwrap()))
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        panic!("Could not locate PKCS 8 private keys.");
    }

    Arc::new(TlsAcceptor::from(Arc::new(
        config.with_single_cert(cert_chain, keys.remove(0)).unwrap(),
    )))
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Item {
    IsAccount(String),
    Authenticate(Credentials<String>),
    Verify(String),
    Expand(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    True,
    False,
    Values(Vec<String>),
}

impl Item {
    pub fn append(&self, append: usize) -> Self {
        match self {
            Item::IsAccount(str) => Item::IsAccount(format!("{append}{str}")),
            Item::Authenticate(str) => Item::Authenticate(match str {
                Credentials::Plain { username, secret } => Credentials::Plain {
                    username: username.to_string(),
                    secret: format!("{append}{secret}"),
                },
                Credentials::OAuthBearer { token } => Credentials::OAuthBearer {
                    token: format!("{append}{token}"),
                },
                Credentials::XOauth2 { username, secret } => Credentials::XOauth2 {
                    username: username.to_string(),
                    secret: format!("{append}{secret}"),
                },
            }),
            Item::Verify(str) => Item::Verify(format!("{append}{str}")),
            Item::Expand(str) => Item::Expand(format!("{append}{str}")),
        }
    }

    pub fn as_credentials(&self) -> &Credentials<String> {
        match self {
            Item::Authenticate(c) => c,
            _ => panic!("Item is not a Credentials"),
        }
    }
}

impl LookupResult {
    fn append(&self, append: usize) -> Self {
        match self {
            LookupResult::True => LookupResult::True,
            LookupResult::False => LookupResult::False,
            LookupResult::Values(v) => {
                let mut r = Vec::with_capacity(v.len());
                for (pos, val) in v.iter().enumerate() {
                    r.push(if pos == 0 {
                        format!("{append}{val}")
                    } else {
                        val.to_string()
                    });
                }
                LookupResult::Values(r)
            }
        }
    }
}

impl From<bool> for LookupResult {
    fn from(b: bool) -> Self {
        if b {
            LookupResult::True
        } else {
            LookupResult::False
        }
    }
}

impl From<Vec<String>> for LookupResult {
    fn from(v: Vec<String>) -> Self {
        LookupResult::Values(v)
    }
}

impl core::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsAccount(arg0) => f.debug_tuple("Rcpt").field(arg0).finish(),
            Self::Authenticate(_) => f.debug_tuple("Auth").finish(),
            Self::Expand(arg0) => f.debug_tuple("Expn").field(arg0).finish(),
            Self::Verify(arg0) => f.debug_tuple("Vrfy").field(arg0).finish(),
        }
    }
}

/*

// DEPRECATED - TODO: Remove
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lookup_local() {
    const LOOKUP_CONFIG: &str = r#"
    [store."local/regex"]
    type = "memory"
    format = "regex"
    values = ["^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
             "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"]

    [store."local/glob"]
    type = "memory"
    format = "glob"
    values = ["*@example.org", "test@*", "localhost", "*+*@*.domain.net"]

    [store."local/list"]
    type = "memory"
    format = "list"
    values = ["abc", "xyz", "123"]

    [store."local/suffix"]
    type = "memory"
    format = "glob"
    comment = "//"
    values = ["https://publicsuffix.org/list/public_suffix_list.dat", "fallback+file://%PATH%/public_suffix_list.dat.gz"]
    "#;

    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    let mut config = utils::config::Config::new(
        &LOOKUP_CONFIG.replace(
            "%PATH%",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .to_path_buf()
                .join("resources")
                .join("config")
                .join("lists")
                .to_str()
                .unwrap(),
        ),
    )
    .unwrap();

    let lookups = Stores::parse_all(&mut config).await.lookup_stores;

    for (lookup, item, expect) in [
        ("glob", "user@example.org", true),
        ("glob", "test@otherdomain.org", true),
        ("glob", "localhost", true),
        ("glob", "john+doe@doefamily.domain.net", true),
        ("glob", "john@domain.net", false),
        ("glob", "example.org", false),
        ("list", "abc", true),
        ("list", "xyz", true),
        ("list", "zzz", false),
        ("regex", "user@domain.com", true),
        ("regex", "127.0.0.1", true),
        ("regex", "hello", false),
        ("suffix", "co.uk", true),
        ("suffix", "coco", false),
    ] {
        assert_eq!(
            lookups
                .get(&format!("local/{lookup}"))
                .unwrap()
                .key_get::<String>(item.as_bytes().to_vec())
                .await
                .unwrap()
                .is_some(),
            expect,
            "failed for {lookup}, item {item}"
        );
    }
}
*/

#[tokio::test]
async fn address_mappings() {
    const MAPPINGS: &str = r#"
    [enable]
    catch-all = true
    subaddressing = true
    expected-sub = "john.doe@example.org"
    expected-sub-nomatch = "jane@example.org"
    expected-catch = "@example.org"

    [disable]
    catch-all = false
    subaddressing = false
    expected-sub = "john.doe+alias@example.org"
    expected-sub-nomatch = "jane@example.org"
    expected-catch = false

    [custom]
    catch-all = [{if = "matches('(.+)@(.+)$', address)", then = "'info@' + $2"}, {else = false}]
    subaddressing = [{ if = "matches('^([^.]+)\\.([^.]+)@(.+)$', address)", then = "$2 + '@' + $3" }, {else = false}]
    expected-sub = "doe+alias@example.org"
    expected-sub-nomatch = "jane@example.org"
    expected-catch = "info@example.org"
    "#;

    let mut config = utils::config::Config::new(MAPPINGS).unwrap();
    const ADDR: &str = "john.doe+alias@example.org";
    const ADDR_NO_MATCH: &str = "jane@example.org";
    let core = Core::default();

    for test in ["enable", "disable", "custom"] {
        let catch_all = AddressMapping::parse(&mut config, (test, "catch-all"));
        let subaddressing = AddressMapping::parse(&mut config, (test, "subaddressing"));

        assert_eq!(
            subaddressing.to_subaddress(&core, ADDR).await,
            config.value_require((test, "expected-sub")).unwrap(),
            "failed subaddress for {test:?}"
        );

        assert_eq!(
            subaddressing.to_subaddress(&core, ADDR_NO_MATCH).await,
            config
                .value_require((test, "expected-sub-nomatch"))
                .unwrap(),
            "failed subaddress no match for {test:?}"
        );

        assert_eq!(
            catch_all.to_catch_all(&core, ADDR).await,
            config
                .property_require::<Option<String>>((test, "expected-catch"))
                .unwrap()
                .map(Cow::Owned),
            "failed catch-all for {test:?}"
        );
    }
}

async fn map_account_ids(store: &Store, names: Vec<impl AsRef<str>>) -> Vec<u32> {
    let mut ids = Vec::with_capacity(names.len());
    for name in names {
        ids.push(store.get_account_id(name.as_ref()).await.unwrap().unwrap());
    }
    ids
}
