use protocol::{
    error::method::MethodError,
    method::import::{ImportEmailRequest, ImportEmailResponse},
};

use crate::JMAP;

impl JMAP {
    pub async fn email_import(
        &self,
        request: ImportEmailRequest,
    ) -> Result<ImportEmailResponse, MethodError> {
        for (id, email) in request.emails {}

        todo!()
    }
}
