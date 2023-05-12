use std::sync::Arc;

use jmap_proto::{
    error::{method::MethodError, request::RequestError},
    method::{get, query, set},
    request::{method::MethodName, Call, Request, RequestMethod},
    response::{Response, ResponseMethod},
    types::collection::Collection,
};

use crate::{auth::AclToken, JMAP};

impl JMAP {
    pub async fn handle_request(
        &self,
        bytes: &[u8],
        acl_token: Arc<AclToken>,
    ) -> Result<Response, RequestError> {
        let request = Request::parse(
            bytes,
            self.config.request_max_calls,
            self.config.request_max_size,
        )?;
        let mut response = Response::new(
            acl_token.state(),
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

                // Add response
                match self
                    .handle_method_call(call.method, &acl_token, &mut next_call)
                    .await
                {
                    Ok(method_response) => {
                        response.push_response(call.id, call.name, method_response);
                    }
                    Err(err) => {
                        response.push_error(call.id, err);
                    }
                }

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

    async fn handle_method_call(
        &self,
        method: RequestMethod,
        acl_token: &AclToken,
        next_call: &mut Option<Call<RequestMethod>>,
    ) -> Result<ResponseMethod, MethodError> {
        Ok(match method {
            RequestMethod::Get(mut req) => match req.take_arguments() {
                get::RequestArguments::Email(arguments) => {
                    acl_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_get(req.with_arguments(arguments), acl_token)
                        .await?
                        .into()
                }
                get::RequestArguments::Mailbox => {
                    acl_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_get(req, acl_token).await?.into()
                }
                get::RequestArguments::Thread => {
                    acl_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.thread_get(req).await?.into()
                }
                get::RequestArguments::Identity => todo!(),
                get::RequestArguments::EmailSubmission => todo!(),
                get::RequestArguments::PushSubscription => todo!(),
                get::RequestArguments::SieveScript => todo!(),
                get::RequestArguments::VacationResponse => todo!(),
                get::RequestArguments::Principal => todo!(),
            },
            RequestMethod::Query(mut req) => match req.take_arguments() {
                query::RequestArguments::Email(arguments) => {
                    acl_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_query(req.with_arguments(arguments), acl_token)
                        .await?
                        .into()
                }
                query::RequestArguments::Mailbox(arguments) => {
                    acl_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_query(req.with_arguments(arguments), acl_token)
                        .await?
                        .into()
                }
                query::RequestArguments::EmailSubmission => todo!(),
                query::RequestArguments::SieveScript => todo!(),
                query::RequestArguments::Principal => todo!(),
            },
            RequestMethod::Set(mut req) => match req.take_arguments() {
                set::RequestArguments::Email => {
                    acl_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_set(req, acl_token).await?.into()
                }
                set::RequestArguments::Mailbox(arguments) => {
                    acl_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_set(req.with_arguments(arguments), acl_token)
                        .await?
                        .into()
                }
                set::RequestArguments::Identity => todo!(),
                set::RequestArguments::EmailSubmission(_) => todo!(),
                set::RequestArguments::PushSubscription => todo!(),
                set::RequestArguments::SieveScript(_) => todo!(),
                set::RequestArguments::VacationResponse => todo!(),
                set::RequestArguments::Principal => todo!(),
            },
            RequestMethod::Changes(req) => self.changes(req, acl_token).await?.into(),
            RequestMethod::Copy(req) => {
                acl_token
                    .assert_has_access(req.account_id, Collection::Email)?
                    .assert_has_access(req.from_account_id, Collection::Email)?;

                self.email_copy(req, acl_token, next_call).await?.into()
            }
            RequestMethod::CopyBlob(req) => self.blob_copy(req, acl_token).await?.into(),
            RequestMethod::ImportEmail(req) => {
                acl_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_import(req, acl_token).await?.into()
            }
            RequestMethod::ParseEmail(req) => {
                acl_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_parse(req, acl_token).await?.into()
            }
            RequestMethod::QueryChanges(req) => self.query_changes(req, acl_token).await?.into(),
            RequestMethod::SearchSnippet(req) => {
                acl_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_search_snippet(req, acl_token).await?.into()
            }
            RequestMethod::ValidateScript(_) => todo!(),
            RequestMethod::Echo(req) => req.into(),
            RequestMethod::Error(error) => return Err(error),
        })
    }
}
