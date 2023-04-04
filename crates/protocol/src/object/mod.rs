pub mod email;
pub mod email_submission;
pub mod mailbox;
pub mod sieve;

use utils::map::vec_map::VecMap;

use crate::types::property::Property;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Object<T> {
    pub properties: VecMap<Property, T>,
}
