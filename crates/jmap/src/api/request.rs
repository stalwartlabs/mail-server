use jmap_proto::{
    error::request::RequestError,
    method::{get, query},
    request::{Request, RequestMethod},
    response::{Response, ResponseMethod},
};

use crate::JMAP;

impl JMAP {
    pub async fn handle_request(&self, bytes: &[u8]) -> Result<Response, RequestError> {
        let request = Request::parse(
            bytes,
            self.config.request_max_calls,
            self.config.request_max_size,
        )?;
        let mut response = Response::new(
            0,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );
        for mut call in request.method_calls {
            // Resolve result and id references
            if let Err(method_error) = response.resolve_references(&mut call.method) {
                response.push_response(call.id, method_error);
                continue;
            }

            let method_response: ResponseMethod = match call.method {
                RequestMethod::Get(mut call) => match call.take_arguments() {
                    get::RequestArguments::Email(arguments) => {
                        self.email_get(call.with_arguments(arguments)).await.into()
                    }
                    get::RequestArguments::Mailbox => todo!(),
                    get::RequestArguments::Thread => todo!(),
                    get::RequestArguments::Identity => todo!(),
                    get::RequestArguments::EmailSubmission => todo!(),
                    get::RequestArguments::PushSubscription => todo!(),
                    get::RequestArguments::SieveScript => todo!(),
                    get::RequestArguments::VacationResponse => todo!(),
                    get::RequestArguments::Principal => todo!(),
                },
                RequestMethod::Query(mut call) => match call.take_arguments() {
                    query::RequestArguments::Email(arguments) => self
                        .email_query(call.with_arguments(arguments))
                        .await
                        .into(),
                    query::RequestArguments::Mailbox(_) => todo!(),
                    query::RequestArguments::EmailSubmission => todo!(),
                    query::RequestArguments::SieveScript => todo!(),
                    query::RequestArguments::Principal => todo!(),
                },
                RequestMethod::Set(_) => todo!(),
                RequestMethod::Changes(_) => todo!(),
                RequestMethod::Copy(_) => todo!(),
                RequestMethod::CopyBlob(_) => todo!(),
                RequestMethod::ImportEmail(call) => self.email_import(call).await.into(),
                RequestMethod::ParseEmail(_) => todo!(),
                RequestMethod::QueryChanges(_) => todo!(),
                RequestMethod::SearchSnippet(_) => todo!(),
                RequestMethod::ValidateScript(_) => todo!(),
                RequestMethod::Echo(call) => call.into(),
                RequestMethod::Error(error) => error.into(),
            };
            response.push_response(call.id, method_response);
        }

        Ok(response)
    }
}
