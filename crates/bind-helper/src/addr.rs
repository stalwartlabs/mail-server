use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use zerocopy::{native_endian, AsBytes, FromBytes, FromZeroes};

#[derive(Default, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct Addr {
    ip: [u8; 16],
    scope_id: native_endian::U32,
    port: native_endian::U16,
    version: u8,
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(v4) => Addr {
                ip: v4.ip().octets().leftpad(0),
                scope_id: 0.into(),
                port: v4.port().into(),
                version: 4,
            },
            SocketAddr::V6(v6) => Addr {
                ip: v6.ip().octets(),
                scope_id: v6.scope_id().into(),
                port: v6.port().into(),
                version: 6,
            },
        }
    }
}

impl From<Addr> for SocketAddr {
    fn from(addr: Addr) -> Self {
        match addr.version {
            4 => SocketAddr::V4(SocketAddrV4::new(
                addr.ip.unleftpad().into(),
                addr.port.get(),
            )),
            6 => SocketAddr::V6(SocketAddrV6::new(
                addr.ip.into(),
                addr.port.get(),
                0,
                addr.scope_id.get(),
            )),
            _ => panic!(),
        }
    }
}

pub trait Leftpad: Copy {
    type T: Copy;
    fn leftpad<const N: usize>(&self, val: Self::T) -> [Self::T; N];
    fn unleftpad<const N: usize>(&self) -> [Self::T; N];
}

impl<T: Copy, const M: usize> Leftpad for [T; M] {
    type T = T;
    fn leftpad<const N: usize>(&self, val: T) -> [T; N] {
        let mut arr = [val; N];
        let back = arr.rchunks_exact_mut(M).next().unwrap();
        back.copy_from_slice(self);
        arr
    }
    fn unleftpad<const N: usize>(&self) -> [T; N] {
        self.rchunks_exact(M).next().unwrap().try_into().unwrap()
    }
}
