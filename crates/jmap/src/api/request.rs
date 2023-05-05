use jmap_proto::{
    error::request::RequestError,
    method::{get, query, set},
    request::{method::MethodName, Request, RequestMethod},
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
                response.push_response(call.id, MethodName::error(), method_error);
                continue;
            }

            loop {
                let mut next_call = None;
                let method_response: ResponseMethod = match call.method {
                    RequestMethod::Get(mut req) => match req.take_arguments() {
                        get::RequestArguments::Email(arguments) => {
                            self.email_get(req.with_arguments(arguments)).await.into()
                        }
                        get::RequestArguments::Mailbox => self.mailbox_get(req).await.into(),
                        get::RequestArguments::Thread => self.thread_get(req).await.into(),
                        get::RequestArguments::Identity => todo!(),
                        get::RequestArguments::EmailSubmission => todo!(),
                        get::RequestArguments::PushSubscription => todo!(),
                        get::RequestArguments::SieveScript => todo!(),
                        get::RequestArguments::VacationResponse => todo!(),
                        get::RequestArguments::Principal => todo!(),
                    },
                    RequestMethod::Query(mut req) => match req.take_arguments() {
                        query::RequestArguments::Email(arguments) => {
                            self.email_query(req.with_arguments(arguments)).await.into()
                        }
                        query::RequestArguments::Mailbox(arguments) => self
                            .mailbox_query(req.with_arguments(arguments))
                            .await
                            .into(),
                        query::RequestArguments::EmailSubmission => todo!(),
                        query::RequestArguments::SieveScript => todo!(),
                        query::RequestArguments::Principal => todo!(),
                    },
                    RequestMethod::Set(mut req) => match req.take_arguments() {
                        set::RequestArguments::Email => self.email_set(req).await.into(),
                        set::RequestArguments::Mailbox(arguments) => {
                            self.mailbox_set(req.with_arguments(arguments)).await.into()
                        }
                        set::RequestArguments::Identity => todo!(),
                        set::RequestArguments::EmailSubmission(_) => todo!(),
                        set::RequestArguments::PushSubscription => todo!(),
                        set::RequestArguments::SieveScript(_) => todo!(),
                        set::RequestArguments::VacationResponse => todo!(),
                        set::RequestArguments::Principal => todo!(),
                    },
                    RequestMethod::Changes(req) => self.changes(req).await.into(),
                    RequestMethod::Copy(req) => self.email_copy(req, &mut next_call).await.into(),
                    RequestMethod::CopyBlob(_) => todo!(),
                    RequestMethod::ImportEmail(req) => self.email_import(req).await.into(),
                    RequestMethod::ParseEmail(req) => self.email_parse(req).await.into(),
                    RequestMethod::QueryChanges(req) => self.query_changes(req).await.into(),
                    RequestMethod::SearchSnippet(req) => {
                        self.email_search_snippet(req).await.into()
                    }
                    RequestMethod::ValidateScript(_) => todo!(),
                    RequestMethod::Echo(req) => req.into(),
                    RequestMethod::Error(error) => error.into(),
                };

                // Add response
                response.push_response(
                    call.id,
                    if !matches!(method_response, ResponseMethod::Error(_)) {
                        call.name
                    } else {
                        MethodName::error()
                    },
                    method_response,
                );

                // Process next call
                if let Some(next_call) = next_call {
                    call = next_call;
                    call.id = response.method_responses.last().unwrap().id.clone();
                } else {
                    break;
                }
            }
        }

        Ok(response)
    }
}
