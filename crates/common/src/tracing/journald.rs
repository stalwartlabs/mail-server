/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use std::io::Write;
use trc::subscriber::SubscriberBuilder;
use trc::{Event, EventDetails, Level, TracingEvent};

pub(crate) fn spawn_journald_tracer(builder: SubscriberBuilder, subscriber: Subscriber) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        while let Some(events) = rx.recv().await {
            for event in events {
                subscriber.send_event(&event);
            }
        }
    });
}

impl Subscriber {
    fn send_event(&self, event: &Event<EventDetails>) {
        let mut buf = Vec::with_capacity(256);
        put_field_wellformed(
            &mut buf,
            "PRIORITY",
            &[match event.inner.level {
                Level::Error => self.priority_mappings.error as u8,
                Level::Warn => self.priority_mappings.warn as u8,
                Level::Info => self.priority_mappings.info as u8,
                Level::Debug => self.priority_mappings.debug as u8,
                Level::Trace | Level::Disable => self.priority_mappings.trace as u8,
            }],
        );
        put_field_length_encoded(&mut buf, "SYSLOG_IDENTIFIER", |buf| {
            write!(buf, "{}", self.syslog_identifier).unwrap()
        });
        put_field_length_encoded(&mut buf, "MESSAGE", |buf| {
            write!(buf, "{}", event.inner.typ.description()).unwrap()
        });

        let mut seen_keys = AHashSet::new();
        for (key, value) in &event.keys {
            if seen_keys.insert(*key) {
                put_field_length_encoded(&mut buf, key.name(), |buf| {
                    write!(buf, "{value}").unwrap()
                });
            }
        }

        if let Err(err) = self.send_payload(&buf) {
            trc::event!(
                Tracing(TracingEvent::JournalError),
                Details = "Failed to send event to journald",
                Reason = err.to_string()
            );
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2018 Benjamin Saunders <ben.e.saunders@gmail.com>
// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::{self, Error, Result};
use std::mem::{size_of, zeroed};
#[cfg(target_os = "linux")]
use std::os::raw::c_uint;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
#[cfg(target_os = "linux")]
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::{AsRawFd, RawFd};
use std::path::Path;
use std::ptr;

use libc::*;

#[cfg(unix)]
const JOURNALD_PATH: &str = "/run/systemd/journal/socket";
const CMSG_BUFSIZE: usize = 64;

pub struct Subscriber {
    #[cfg(unix)]
    socket: UnixDatagram,
    syslog_identifier: String,
    priority_mappings: PriorityMappings,
}

#[derive(Debug, Clone)]
pub struct PriorityMappings {
    /// Priority mapped to the `ERROR` level
    pub error: Priority,
    /// Priority mapped to the `WARN` level
    pub warn: Priority,
    /// Priority mapped to the `INFO` level
    pub info: Priority,
    /// Priority mapped to the `DEBUG` level
    pub debug: Priority,
    /// Priority mapped to the `TRACE` level
    pub trace: Priority,
}

#[repr(C)]
union AlignedBuffer<T: Copy + Clone> {
    buffer: T,
    align: cmsghdr,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Priority {
    /// System is unusable.
    ///
    /// Examples:
    ///
    /// - severe Kernel BUG
    /// - systemd dumped core
    ///
    /// This level should not be used by applications.
    Emergency = b'0',
    /// Should be corrected immediately.
    ///
    /// Examples:
    ///
    /// - Vital subsystem goes out of work, data loss:
    /// - `kernel: BUG: unable to handle kernel paging request at ffffc90403238ffc`
    Alert = b'1',
    /// Critical conditions
    ///
    /// Examples:
    ///
    /// - Crashe, coredumps
    /// - `systemd-coredump[25319]: Process 25310 (plugin-container) of user 1000 dumped core`
    Critical = b'2',
    /// Error conditions
    ///
    /// Examples:
    ///
    /// - Not severe error reported
    /// - `kernel: usb 1-3: 3:1: cannot get freq at ep 0x84, systemd[1]: Failed unmounting /var`
    /// - `libvirtd[1720]: internal error: Failed to initialize a valid firewall backend`
    Error = b'3',
    /// May indicate that an error will occur if action is not taken.
    ///
    /// Examples:
    ///
    /// - a non-root file system has only 1GB free
    /// - `org.freedesktop. Notifications[1860]: (process:5999): Gtk-WARNING **: Locale not supported by C library. Using the fallback 'C' locale`
    Warning = b'4',
    /// Events that are unusual, but not error conditions.
    ///
    /// Examples:
    ///
    /// - `systemd[1]: var.mount: Directory /var to mount over is not empty, mounting anyway`
    /// - `gcr-prompter[4997]: Gtk: GtkDialog mapped without a transient parent. This is discouraged`
    Notice = b'5',
    /// Normal operational messages that require no action.
    ///
    /// Example: `lvm[585]: 7 logical volume(s) in volume group "archvg" now active`
    Informational = b'6',
    /// Information useful to developers for debugging the
    /// application.
    ///
    /// Example: `kdeinit5[1900]: powerdevil: Scheduling inhibition from ":1.14" "firefox" with cookie 13 and reason "screen"`
    Debug = b'7',
}

impl Subscriber {
    /// Construct a journald subscriber
    ///
    /// Fails if the journald socket couldn't be opened. Returns a `NotFound` error unconditionally
    /// in non-Unix environments.
    pub fn new() -> io::Result<Self> {
        #[cfg(unix)]
        {
            let socket = UnixDatagram::unbound()?;
            let sub = Self {
                socket,
                syslog_identifier: std::env::current_exe()
                    .ok()
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    // If we fail to get the name of the current executable fall back to an empty string.
                    .unwrap_or_default(),
                priority_mappings: PriorityMappings::new(),
            };
            // Check that we can talk to journald, by sending empty payload which journald discards.
            // However if the socket didn't exist or if none listened we'd get an error here.
            sub.send_payload(&[])?;
            Ok(sub)
        }
        #[cfg(not(unix))]
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "journald does not exist in this environment",
        ))
    }

    /// Sets how [`tracing_core::Level`]s are mapped to [journald priorities](Priority).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tracing_journald::{Priority, PriorityMappings};
    /// use tracing_subscriber::prelude::*;
    /// use tracing::error;
    ///
    /// let registry = tracing_subscriber::registry();
    /// match tracing_journald::subscriber() {
    ///     Ok(subscriber) => {
    ///         registry.with(
    ///             subscriber
    ///                 // We can tweak the mappings between the trace level and
    ///                 // the journal priorities.
    ///                 .with_priority_mappings(PriorityMappings {
    ///                     info: Priority::Informational,
    ///                     ..PriorityMappings::new()
    ///                 }),
    ///         );
    ///     }
    ///     // journald is typically available on Linux systems, but nowhere else. Portable software
    ///     // should handle its absence gracefully.
    ///     Err(e) => {
    ///         registry.init();
    ///         error!("couldn't connect to journald: {}", e);
    ///     }
    /// }
    /// ```
    pub fn with_priority_mappings(mut self, mappings: PriorityMappings) -> Self {
        self.priority_mappings = mappings;
        self
    }

    /// Sets the syslog identifier for this logger.
    ///
    /// The syslog identifier comes from the classic syslog interface (`openlog()`
    /// and `syslog()`) and tags log entries with a given identifier.
    /// Systemd exposes it in the `SYSLOG_IDENTIFIER` journal field, and allows
    /// filtering log messages by syslog identifier with `journalctl -t`.
    /// Unlike the unit (`journalctl -u`) this field is not trusted, i.e. applications
    /// can set it freely, and use it e.g. to further categorize log entries emitted under
    /// the same systemd unit or in the same process.  It also allows to filter for log
    /// entries of processes not started in their own unit.
    ///
    /// See [Journal Fields](https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html)
    /// and [journalctl](https://www.freedesktop.org/software/systemd/man/journalctl.html)
    /// for more information.
    ///
    /// Defaults to the file name of the executable of the current process, if any.
    pub fn with_syslog_identifier(mut self, identifier: String) -> Self {
        self.syslog_identifier = identifier;
        self
    }

    /// Returns the syslog identifier in use.
    pub fn syslog_identifier(&self) -> &str {
        &self.syslog_identifier
    }

    #[cfg(not(unix))]
    fn send_payload(&self, _opayload: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "journald not supported on non-Unix",
        ))
    }

    #[cfg(unix)]
    fn send_payload(&self, payload: &[u8]) -> io::Result<usize> {
        self.socket
            .send_to(payload, JOURNALD_PATH)
            .or_else(|error| {
                if Some(libc::EMSGSIZE) == error.raw_os_error() {
                    self.send_large_payload(payload)
                } else {
                    Err(error)
                }
            })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn send_large_payload(&self, _payload: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Large payloads not supported on non-Linux OS",
        ))
    }

    /// Send large payloads to journald via a memfd.
    #[cfg(target_os = "linux")]
    fn send_large_payload(&self, payload: &[u8]) -> io::Result<usize> {
        // If the payload's too large for a single datagram, send it through a memfd, see
        // https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
        use std::os::unix::prelude::AsRawFd;
        // Write the whole payload to a memfd
        let mut mem = create_sealable()?;
        mem.write_all(payload)?;
        // Fully seal the memfd to signal journald that its backing data won't resize anymore
        // and so is safe to mmap.
        seal_fully(mem.as_raw_fd())?;
        send_one_fd_to(&self.socket, mem.as_raw_fd(), JOURNALD_PATH)
    }
}

impl PriorityMappings {
    /// Returns the default priority mappings:
    ///
    /// - [`tracing::Level::ERROR`]: [`Priority::Error`] (3)
    /// - [`tracing::Level::WARN`]: [`Priority::Warning`] (4)
    /// - [`tracing::Level::INFO`]: [`Priority::Notice`] (5)
    /// - [`tracing::Level::DEBUG`]: [`Priority::Informational`] (6)
    /// - [`tracing::Level::TRACE`]: [`Priority::Debug`] (7)
    pub fn new() -> PriorityMappings {
        Self {
            error: Priority::Error,
            warn: Priority::Warning,
            info: Priority::Notice,
            debug: Priority::Informational,
            trace: Priority::Debug,
        }
    }
}

impl Default for PriorityMappings {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscriber")
            .field("socket", &self.socket)
            .field("syslog_identifier", &self.syslog_identifier)
            .field("priority_mappings", &self.priority_mappings)
            .finish()
    }
}

/// Append a sanitized and length-encoded field into `buf`.
///
/// Unlike `put_field_wellformed` this function handles arbitrary field names and values.
///
/// `name` denotes the field name. It gets sanitized before being appended to `buf`.
///
/// `write_value` is invoked with `buf` as argument to append the value data to `buf`.  It must
/// not delete from `buf`, but may append arbitrary data.  This function then determines the length
/// of the data written and adds it in the appropriate place in `buf`.
fn put_field_length_encoded(buf: &mut Vec<u8>, name: &str, write_value: impl FnOnce(&mut Vec<u8>)) {
    for ch in name.as_bytes() {
        buf.push(ch.to_ascii_uppercase());
    }
    buf.push(b'\n');
    buf.extend_from_slice(&[0; 8]); // Length tag, to be populated
    let start = buf.len();
    write_value(buf);
    let end = buf.len();
    buf[start - 8..start].copy_from_slice(&((end - start) as u64).to_le_bytes());
    buf.push(b'\n');
}

/// Append arbitrary data with a well-formed name and value.
///
/// `value` must not contain an internal newline, because this function writes
/// `value` in the new-line separated format.
///
/// For a "newline-safe" variant, see `put_field_length_encoded`.
fn put_field_wellformed(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'\n');
    put_value(buf, value);
}

/// Write the value portion of a key-value pair, in newline separated format.
///
/// `value` must not contain an internal newline.
///
/// For a "newline-safe" variant, see `put_field_length_encoded`.
fn put_value(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value);
    buf.push(b'\n');
}

fn assert_cmsg_bufsize() {
    let space_one_fd = unsafe { CMSG_SPACE(size_of::<RawFd>() as u32) };
    assert!(
        space_one_fd <= CMSG_BUFSIZE as u32,
        "cmsghdr buffer too small (< {}) to hold a single fd",
        space_one_fd
    );
}

pub fn send_one_fd_to<P: AsRef<Path>>(socket: &UnixDatagram, fd: RawFd, path: P) -> Result<usize> {
    assert_cmsg_bufsize();

    let mut addr: sockaddr_un = unsafe { zeroed() };
    let path_bytes = path.as_ref().as_os_str().as_bytes();
    // path_bytes may have at most sun_path + 1 bytes, to account for the trailing NUL byte.
    if addr.sun_path.len() <= path_bytes.len() {
        return Err(Error::from_raw_os_error(ENAMETOOLONG));
    }

    addr.sun_family = AF_UNIX as _;
    unsafe {
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            addr.sun_path.as_mut_ptr() as *mut u8,
            path_bytes.len(),
        )
    };

    let mut msg: msghdr = unsafe { zeroed() };
    // Set the target address.
    msg.msg_name = &mut addr as *mut _ as *mut c_void;
    msg.msg_namelen = size_of::<sockaddr_un>() as socklen_t;

    // We send no data body with this message.
    msg.msg_iov = ptr::null_mut();
    msg.msg_iovlen = 0;

    // Create and fill the control message buffer with our file descriptor
    let mut cmsg_buffer = AlignedBuffer {
        buffer: ([0u8; CMSG_BUFSIZE]),
    };
    msg.msg_control = unsafe { cmsg_buffer.buffer.as_mut_ptr() as _ };
    msg.msg_controllen = unsafe { CMSG_SPACE(size_of::<RawFd>() as _) as _ };

    let cmsg: &mut cmsghdr =
        unsafe { CMSG_FIRSTHDR(&msg).as_mut() }.expect("Control message buffer exhausted");

    cmsg.cmsg_level = SOL_SOCKET;
    cmsg.cmsg_type = SCM_RIGHTS;
    cmsg.cmsg_len = unsafe { CMSG_LEN(size_of::<RawFd>() as _) as _ };

    unsafe { ptr::write(CMSG_DATA(cmsg) as *mut RawFd, fd) };

    let result = unsafe { sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };

    if result < 0 {
        Err(Error::last_os_error())
    } else {
        // sendmsg returns the number of bytes written
        Ok(result as usize)
    }
}

#[cfg(target_os = "linux")]
fn create(flags: c_uint) -> Result<File> {
    let fd = memfd_create_syscall(flags);
    if fd < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
}

/// Make the `memfd_create` syscall ourself instead of going through `libc`;
/// `memfd_create` isn't supported on `glibc<2.27` so this allows us to
/// support old-but-still-used distros like Ubuntu Xenial, Debian Stretch,
/// RHEL 7, etc.
///
/// See: https://github.com/tokio-rs/tracing/issues/1879
#[cfg(target_os = "linux")]
fn memfd_create_syscall(flags: c_uint) -> c_int {
    unsafe {
        syscall(
            SYS_memfd_create,
            "tracing-journald\0".as_ptr() as *const c_char,
            flags,
        ) as c_int
    }
}

#[cfg(target_os = "linux")]
pub fn create_sealable() -> Result<File> {
    create(MFD_ALLOW_SEALING | MFD_CLOEXEC)
}

#[cfg(target_os = "linux")]
pub fn seal_fully(fd: RawFd) -> Result<()> {
    let all_seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    let result = unsafe { fcntl(fd, F_ADD_SEALS, all_seals) };
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}
// SPDX-SnippetEnd
