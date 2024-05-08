use crate::addr::Addr;

use zerocopy::AsBytes;

use std::{
    io::{IoSlice, IoSliceMut, Read, Write},
    net::SocketAddr,
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
};

use nix::{
    cmsg_space,
    errno::Errno,
    sys::socket::{self, ControlMessage, MsgFlags, SockaddrStorage},
    unistd::ForkResult,
};

const BATCH_SIZE: usize = 16;

fn privileged_helper(mut peer: UnixStream) {
    let mut cmsg_buffer = cmsg_space!([RawFd; BATCH_SIZE]);
    let mut addrs = [Addr::default(); BATCH_SIZE];
    let mut return_values = [0; BATCH_SIZE];
    loop {
        let (fds, bytes) = {
            let mut iov = [IoSliceMut::new(addrs.as_bytes_mut())];
            let recvmsg = socket::recvmsg::<()>(
                peer.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buffer),
                MsgFlags::empty(),
            )
            .unwrap();

            if recvmsg.bytes == 0 {
                break;
            }

            let fds = recvmsg.cmsgs().find_map(|cmsg| match cmsg {
                socket::ControlMessageOwned::ScmRights(r) => Some(r),
                _ => None,
            });

            (fds.unwrap(), recvmsg.bytes)
        };

        let addrs = &mut addrs[..fds.len()];
        let return_values = &mut return_values[..fds.len()];

        peer.read_exact(&mut addrs.as_bytes_mut()[bytes..]).unwrap();

        for ((addr, fd), return_value) in addrs
            .iter()
            .zip(fds.iter().copied())
            .zip(return_values.iter_mut())
        {
            let sockaddr = SocketAddr::from(*addr);
            let fd = RawFd::from(fd);
            let ret = socket::bind(fd, &SockaddrStorage::from(sockaddr));
            *return_value = match ret {
                Err(Errno::UnknownErrno) => i32::MAX,
                Err(e) => e as i32,
                Ok(()) => 0,
            };
            nix::unistd::close(fd).unwrap();
        }

        peer.write_all(return_values.as_bytes_mut()).unwrap();
    }
}

#[cfg(unix)]
pub struct Helper(UnixStream);

// Safety: fork is safe if that's the first thing the main function does.
// Especially, do not create any threads and do not modify any global state,
// which also implys using stdin or stdout (because of buffering),
// before this fork call. This also implies adding `#[tokio::main]` attributes
// or similar to your inner main function instead of the real main.
pub unsafe fn start_privileged_helper() -> Helper {
    // The socketpair call is safe before fork. Make sure to drop
    // the unneeded side immediately in both the child and the parent.
    let (parent_sock, child_sock) = UnixStream::pair().unwrap();

    if let ForkResult::Child = nix::unistd::fork().unwrap() {
        drop(parent_sock);
        privileged_helper(child_sock);
        std::process::exit(0);
    } else {
        drop(child_sock);
        Helper(parent_sock)
    }
}

impl Helper {
    pub fn bind_sockets(&mut self, sockets: &[(RawFd, SocketAddr)]) -> Vec<i32> {
        let mut result = vec![i32::MAX; sockets.len()];
        for (batch, batch_result) in sockets
            .chunks(BATCH_SIZE)
            .zip(result.chunks_mut(BATCH_SIZE))
        {
            let fds: Vec<_> = batch.iter().copied().map(|(fd, _)| fd).collect();
            let data: Vec<_> = batch.iter().map(|&(_, addr)| Addr::from(addr)).collect();

            let iov = [IoSlice::new(data.as_bytes())];
            socket::sendmsg::<()>(
                self.0.as_raw_fd(),
                &iov,
                &[ControlMessage::ScmRights(&fds[..])],
                MsgFlags::empty(),
                None,
            )
            .unwrap();

            self.0.read_exact(batch_result.as_bytes_mut()).unwrap();
        }
        result
    }
}
