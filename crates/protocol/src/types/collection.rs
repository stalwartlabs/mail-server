#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Collection {
    Principal = 0,
    PushSubscription = 1,
    Mail = 2,
    Mailbox = 3,
    Thread = 4,
    Identity = 5,
    EmailSubmission = 6,
    SieveScript = 7,
}
