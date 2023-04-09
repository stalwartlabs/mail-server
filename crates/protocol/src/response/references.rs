use crate::{
    error::method::MethodError,
    request::{
        method::MethodFunction,
        reference::{MaybeReference, ResultReference},
        Request, RequestMethod,
    },
    types::{id::Id, pointer::JSONPointer, property::Property, value::Value},
};

use super::{Response, ResponseMethod};

enum EvalResult {
    Properties(Vec<Property>),
    Values(Vec<Value>),
    Failed,
}

impl Response {
    pub fn resolve_references(&self, request: &mut RequestMethod) -> Result<(), MethodError> {
        match request {
            RequestMethod::Get(request) => {
                // Resolve id references
                if let Some(MaybeReference::Reference(reference)) = &request.ids {
                    request.ids = Some(MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_ids(reference)?,
                    ));
                }

                // Resolve properties references
                if let Some(MaybeReference::Reference(reference)) = &request.properties {
                    request.properties = Some(MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_properties(reference)?,
                    ));
                }
            }
            RequestMethod::Set(request) => {
                // Resolve destroy references
                if let Some(MaybeReference::Reference(reference)) = &request.destroy {
                    request.destroy = Some(MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_ids(reference)?,
                    ));
                }
            }
            RequestMethod::Changes(_) => todo!(),
            RequestMethod::Copy(_) => todo!(),
            RequestMethod::CopyBlob(_) => todo!(),
            RequestMethod::ImportEmail(_) => todo!(),
            RequestMethod::ParseEmail(_) => todo!(),
            RequestMethod::QueryChanges(_) => todo!(),
            RequestMethod::Query(_) => todo!(),
            RequestMethod::SearchSnippet(request) => {
                // Resolve emailIds references
                if let MaybeReference::Reference(reference) = &request.email_ids {
                    request.email_ids = MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_ids(reference)?,
                    );
                }
            }
            RequestMethod::ValidateScript(_) => todo!(),
            RequestMethod::Echo(_) => todo!(),
            RequestMethod::Error(_) => todo!(),
        }

        Ok(())
    }

    fn eval_result_references(&self, rr: &ResultReference) -> EvalResult {
        for response in &self.method_responses {
            if response.id == rr.result_of {
                match (&rr.name.fnc, &response.method) {
                    (MethodFunction::Get, ResponseMethod::Get(response)) => {
                        return match rr.path.item_subquery() {
                            Some((root, property)) if root == "list" => {
                                let property = Property::parse(property);

                                EvalResult::Values(
                                    response
                                        .list
                                        .iter()
                                        .filter_map(|obj| obj.properties.get(&property).cloned())
                                        .collect(),
                                )
                            }
                            _ => EvalResult::Failed,
                        };
                    }
                    (MethodFunction::Changes, ResponseMethod::Changes(response)) => {
                        return match rr.path.item_query() {
                            Some("created") => EvalResult::Values(
                                response
                                    .created
                                    .clone()
                                    .into_iter()
                                    .map(Into::into)
                                    .collect(),
                            ),
                            Some("updated") => EvalResult::Values(
                                response
                                    .updated
                                    .clone()
                                    .into_iter()
                                    .map(Into::into)
                                    .collect(),
                            ),
                            Some("updatedProperties") => EvalResult::Properties(
                                response.updated_properties.clone().unwrap_or_default(),
                            ),
                            _ => EvalResult::Failed,
                        };
                    }
                    (MethodFunction::Query, ResponseMethod::Query(response)) => {
                        return if rr.path.item_query() == Some("ids") {
                            EvalResult::Values(
                                response.ids.iter().copied().map(Into::into).collect(),
                            )
                        } else {
                            EvalResult::Failed
                        };
                    }
                    (MethodFunction::QueryChanges, ResponseMethod::QueryChanges(response)) => {
                        return if rr.path.item_subquery() == Some(("added", "id")) {
                            EvalResult::Values(
                                response.added.iter().map(|item| item.id.into()).collect(),
                            )
                        } else {
                            EvalResult::Failed
                        };
                    }
                    _ => (),
                }
            }
        }

        EvalResult::Failed
    }
}

impl EvalResult {
    pub fn unwrap_ids(self, rr: &ResultReference) -> Result<Vec<Id>, MethodError> {
        if let EvalResult::Values(values) = self {
            let mut ids = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Value::Id(id) => ids.push(id),
                    Value::List(list) => {
                        for value in list {
                            if let Value::Id(id) = value {
                                ids.push(id);
                            } else {
                                return Err(MethodError::InvalidResultReference(format!(
                                    "Failed to evaluate {rr} result reference."
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(MethodError::InvalidResultReference(format!(
                            "Failed to evaluate {rr} result reference."
                        )))
                    }
                }
            }
            Ok(ids)
        } else {
            Err(MethodError::InvalidResultReference(format!(
                "Failed to evaluate {rr} result reference."
            )))
        }
    }

    pub fn unwrap_properties(self, rr: &ResultReference) -> Result<Vec<Property>, MethodError> {
        if let EvalResult::Properties(properties) = self {
            Ok(properties)
        } else {
            Err(MethodError::InvalidResultReference(format!(
                "Failed to evaluate {rr} result reference."
            )))
        }
    }
}
