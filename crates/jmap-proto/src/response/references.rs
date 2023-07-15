/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::collections::HashMap;

use utils::map::vec_map::VecMap;

use crate::{
    error::{method::MethodError, set::SetError},
    method::{copy::CopyResponse, set::SetResponse},
    object::Object,
    request::{
        reference::{MaybeReference, ResultReference},
        RequestMethod,
    },
    types::{
        id::Id,
        property::Property,
        value::{MaybePatchValue, SetValue, Value},
    },
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
                // Resolve create references
                if let Some(create) = &mut request.create {
                    let mut graph = HashMap::with_capacity(create.len());
                    for (id, obj) in create.iter_mut() {
                        self.eval_object_references(obj, Some((&*id, &mut graph)))?;
                    }

                    // Perform topological sort
                    if !graph.is_empty() {
                        // Make sure all references exist
                        for (from_id, to_ids) in graph.iter() {
                            for to_id in to_ids {
                                if !create.contains_key(to_id) {
                                    return Err(MethodError::InvalidResultReference(format!(
                                        "Invalid reference to non-existing object {to_id:?} from {from_id:?}"
                                    )));
                                }
                            }
                        }

                        let mut sorted_create = VecMap::with_capacity(create.len());
                        let mut it_stack = Vec::new();
                        let keys = graph.keys().cloned().collect::<Vec<_>>();
                        let mut it = keys.iter();

                        'main: loop {
                            while let Some(from_id) = it.next() {
                                if let Some(to_ids) = graph.get(from_id) {
                                    it_stack.push((it, from_id));
                                    if it_stack.len() > 1000 {
                                        return Err(MethodError::InvalidArguments(
                                            "Cyclical references are not allowed.".to_string(),
                                        ));
                                    }
                                    it = to_ids.iter();
                                    continue;
                                } else if let Some((id, value)) = create.remove_entry(from_id) {
                                    sorted_create.append(id, value);
                                    if create.is_empty() {
                                        break 'main;
                                    }
                                }
                            }

                            if let Some((prev_it, from_id)) = it_stack.pop() {
                                it = prev_it;
                                if let Some((id, value)) = create.remove_entry(from_id) {
                                    sorted_create.append(id, value);
                                    if create.is_empty() {
                                        break 'main;
                                    }
                                }
                            } else {
                                break;
                            }
                        }

                        // Add remaining items
                        if !create.is_empty() {
                            for (id, value) in std::mem::take(create) {
                                sorted_create.append(id, value);
                            }
                        }
                        request.create = sorted_create.into();
                    }
                }

                // Resolve update references
                if let Some(update) = &mut request.update {
                    for obj in update.values_mut() {
                        self.eval_object_references(obj, None)?;
                    }
                }

                // Resolve destroy references
                if let Some(MaybeReference::Reference(reference)) = &request.destroy {
                    request.destroy = Some(MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_ids(reference)?,
                    ));
                }
            }
            RequestMethod::Copy(request) => {
                // Resolve create references
                for (id, obj) in request.create.iter_mut() {
                    self.eval_object_references(obj, None)?;
                    if let MaybeReference::Reference(ir) = id {
                        *id = MaybeReference::Value(self.eval_id_reference(ir)?);
                    }
                }
            }
            RequestMethod::ImportEmail(request) => {
                // Resolve email mailbox references
                for email in request.emails.values_mut() {
                    match &mut email.mailbox_ids {
                        MaybeReference::Reference(rr) => {
                            email.mailbox_ids = MaybeReference::Value(
                                self.eval_result_references(rr)
                                    .unwrap_ids(rr)?
                                    .into_iter()
                                    .map(MaybeReference::Value)
                                    .collect(),
                            );
                        }
                        MaybeReference::Value(values) => {
                            for value in values {
                                if let MaybeReference::Reference(ir) = value {
                                    *value = MaybeReference::Value(self.eval_id_reference(ir)?);
                                }
                            }
                        }
                    }
                }
            }
            RequestMethod::SearchSnippet(request) => {
                // Resolve emailIds references
                if let MaybeReference::Reference(reference) = &request.email_ids {
                    request.email_ids = MaybeReference::Value(
                        self.eval_result_references(reference)
                            .unwrap_ids(reference)?,
                    );
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn eval_result_references(&self, rr: &ResultReference) -> EvalResult {
        for response in &self.method_responses {
            if response.id == rr.result_of && response.name == rr.name {
                match &response.method {
                    ResponseMethod::Get(response) => {
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
                    ResponseMethod::Changes(response) => {
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
                    ResponseMethod::Query(response) => {
                        return if rr.path.item_query() == Some("ids") {
                            EvalResult::Values(
                                response.ids.iter().copied().map(Into::into).collect(),
                            )
                        } else {
                            EvalResult::Failed
                        };
                    }
                    ResponseMethod::QueryChanges(response) => {
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

    fn eval_id_reference(&self, ir: &str) -> Result<Id, MethodError> {
        if let Some(id) = self.created_ids.get(ir) {
            Ok(*id)
        } else {
            Err(MethodError::InvalidResultReference(format!(
                "Id reference {ir:?} not found."
            )))
        }
    }

    fn eval_object_references(
        &self,
        obj: &mut Object<SetValue>,
        mut graph: Option<(&str, &mut HashMap<String, Vec<String>>)>,
    ) -> Result<(), MethodError> {
        for set_value in obj.properties.values_mut() {
            match set_value {
                SetValue::IdReference(MaybeReference::Reference(parent_id)) => {
                    if let Some(id) = self.created_ids.get(parent_id) {
                        *set_value = SetValue::Value(Value::Id(*id));
                    } else if let Some((child_id, graph)) = &mut graph {
                        graph
                            .entry(child_id.to_string())
                            .or_insert_with(Vec::new)
                            .push(parent_id.to_string());
                    } else {
                        return Err(MethodError::InvalidResultReference(format!(
                            "Id reference {parent_id:?} not found."
                        )));
                    }
                }
                SetValue::IdReferences(id_refs) => {
                    for id_ref in id_refs {
                        if let MaybeReference::Reference(parent_id) = id_ref {
                            if let Some(id) = self.created_ids.get(parent_id) {
                                *id_ref = MaybeReference::Value(*id);
                            } else if let Some((child_id, graph)) = &mut graph {
                                graph
                                    .entry(child_id.to_string())
                                    .or_insert_with(Vec::new)
                                    .push(parent_id.to_string());
                            } else {
                                return Err(MethodError::InvalidResultReference(format!(
                                    "Id reference {parent_id:?} not found."
                                )));
                            }
                        }
                    }
                }
                SetValue::ResultReference(rr) => {
                    *set_value =
                        SetValue::Value(self.eval_result_references(rr).unwrap_ids(rr)?.into());
                }
                _ => (),
            }
        }

        Ok(())
    }
}

pub trait EvalObjectReferences {
    fn get_id(&self, id_ref: &str) -> Option<&Id>;

    fn eval_object_references(&self, set_value: SetValue) -> Result<MaybePatchValue, SetError> {
        match set_value {
            SetValue::Value(value) => Ok(MaybePatchValue::Value(value)),
            SetValue::Patch(patch) => Ok(MaybePatchValue::Patch(patch)),
            SetValue::IdReference(MaybeReference::Reference(id_ref)) => {
                if let Some(id) = self.get_id(&id_ref) {
                    Ok(MaybePatchValue::Value(Value::Id(*id)))
                } else {
                    Err(SetError::not_found()
                        .with_description(format!("Id reference {id_ref:?} not found.")))
                }
            }
            SetValue::IdReference(MaybeReference::Value(id)) => {
                Ok(MaybePatchValue::Value(Value::Id(id)))
            }
            SetValue::IdReferences(id_refs) => {
                let mut ids = Vec::with_capacity(id_refs.len());
                for id_ref in id_refs {
                    match id_ref {
                        MaybeReference::Value(id) => {
                            ids.push(Value::Id(id));
                        }
                        MaybeReference::Reference(id_ref) => {
                            if let Some(id) = self.get_id(&id_ref) {
                                ids.push(Value::Id(*id));
                            } else {
                                return Err(SetError::not_found().with_description(format!(
                                    "Id reference {id_ref:?} not found."
                                )));
                            }
                        }
                    }
                }
                Ok(MaybePatchValue::Value(Value::List(ids)))
            }
            _ => unreachable!(),
        }
    }
}

impl EvalObjectReferences for SetResponse {
    fn get_id(&self, id_ref: &str) -> Option<&Id> {
        self.created
            .get(id_ref)
            .and_then(|obj| obj.properties.get(&Property::Id))
            .and_then(|v| v.as_id())
    }
}

impl EvalObjectReferences for CopyResponse {
    fn get_id(&self, _id_ref: &str) -> Option<&Id> {
        None
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        error::method::MethodError,
        request::{Request, RequestMethod},
        response::Response,
        types::{
            id::Id,
            property::Property,
            value::{SetValue, Value},
        },
    };

    #[test]
    fn eval_references() {
        let request = Request::parse(
            br##"{
                    "using": [
                        "urn:ietf:params:jmap:core",
                        "urn:ietf:params:jmap:mail"
                    ],
                    "methodCalls": [
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a": {
                                        "name": "Folder a",
                                        "parentId": "#b"
                                    },
                                    "b": {
                                        "name": "Folder b",
                                        "parentId": "#c"
                                    },
                                    "c": {
                                        "name": "Folder c",
                                        "parentId": "#d"
                                    },
                                    "d": {
                                        "name": "Folder d",
                                        "parentId": "#e"
                                    },
                                    "e": {
                                        "name": "Folder e",
                                        "parentId": "#f"
                                    },
                                    "f": {
                                        "name": "Folder f",
                                        "parentId": "#g"
                                    },
                                    "g": {
                                        "name": "Folder g",
                                        "parentId": null
                                    }
                                }
                            },
                            "fulltree"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a1": {
                                        "name": "Folder a1",
                                        "parentId": null
                                    },
                                    "b2": {
                                        "name": "Folder b2",
                                        "parentId": "#a1"
                                    },
                                    "c3": {
                                        "name": "Folder c3",
                                        "parentId": "#a1"
                                    },
                                    "d4": {
                                        "name": "Folder d4",
                                        "parentId": "#b2"
                                    },
                                    "e5": {
                                        "name": "Folder e5",
                                        "parentId": "#b2"
                                    },
                                    "f6": {
                                        "name": "Folder f6",
                                        "parentId": "#d4"
                                    },
                                    "g7": {
                                        "name": "Folder g7",
                                        "parentId": "#e5"
                                    }
                                }
                            },
                            "fulltree2"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "z": {
                                        "name": "Folder Z",
                                        "parentId": "#x"
                                    },
                                    "y": {
                                        "name": null
                                    },
                                    "x": {
                                        "name": "Folder X"
                                    }
                                }
                            },
                            "xyz"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a": {
                                        "name": "Folder a",
                                        "parentId": "#b"
                                    },
                                    "b": {
                                        "name": "Folder b",
                                        "parentId": "#c"
                                    },
                                    "c": {
                                        "name": "Folder c",
                                        "parentId": "#d"
                                    },
                                    "d": {
                                        "name": "Folder d",
                                        "parentId": "#a"
                                    }
                                }
                            },
                            "circular"
                        ]
                    ]
                }"##,
            100,
            1024 * 1024,
        )
        .unwrap();

        let response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        for (test_num, mut call) in request.method_calls.into_iter().enumerate() {
            match response.resolve_references(&mut call.method) {
                Ok(_) => assert!(
                    (0..3).contains(&test_num),
                    "Unexpected invocation {}",
                    test_num
                ),
                Err(err) => {
                    assert_eq!(test_num, 3);
                    assert!(matches!(err, MethodError::InvalidArguments(_)));
                    continue;
                }
            }

            if let RequestMethod::Set(request) = call.method {
                if test_num == 0 {
                    assert_eq!(
                        request
                            .create
                            .unwrap()
                            .into_iter()
                            .map(|b| b.0)
                            .collect::<Vec<_>>(),
                        ["g", "f", "e", "d", "c", "b", "a"]
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                    );
                } else if test_num == 1 {
                    let mut pending_ids = vec!["a1", "b2", "d4", "e5", "f6", "c3", "g7"];

                    for (id, _) in request.create.as_ref().unwrap() {
                        match id.as_str() {
                            "a1" => (),
                            "b2" | "c3" => assert!(!pending_ids.contains(&"a1")),
                            "d4" | "e5" => assert!(!pending_ids.contains(&"b2")),
                            "f6" => assert!(!pending_ids.contains(&"d4")),
                            "g7" => assert!(!pending_ids.contains(&"e5")),
                            _ => panic!("Unexpected ID"),
                        }
                        pending_ids.retain(|i| i != id);
                    }

                    if !pending_ids.is_empty() {
                        panic!(
                            "Unexpected order: {:?}",
                            request
                                .create
                                .as_ref()
                                .unwrap()
                                .iter()
                                .map(|b| b.0.to_string())
                                .collect::<Vec<_>>()
                        );
                    }
                } else if test_num == 2 {
                    assert_eq!(
                        request
                            .create
                            .unwrap()
                            .into_iter()
                            .map(|b| b.0)
                            .collect::<Vec<_>>(),
                        ["x", "z", "y"]
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                    );
                }
            } else {
                panic!("Expected Set Mailbox Request");
            }
        }

        let request = Request::parse(
            br##"{
                "using": [
                    "urn:ietf:params:jmap:core",
                    "urn:ietf:params:jmap:mail"
                ],
                "methodCalls": [
                    [
                        "Mailbox/set",
                        {
                            "accountId": "b",
                            "create": {
                                "a": {
                                    "name": "a",
                                    "parentId": "#x"
                                },
                                "b": {
                                    "name": "b",
                                    "parentId": "#y"
                                },
                                "c": {
                                    "name": "c",
                                    "parentId": "#z"
                                }
                            }
                        },
                        "ref1"
                    ],
                    [
                        "Mailbox/set",
                        {
                            "accountId": "b",
                            "create": {
                                "a1": {
                                    "name": "a1",
                                    "parentId": "#a"
                                },
                                "b2": {
                                    "name": "b2",
                                    "parentId": "#b"
                                },
                                "c3": {
                                    "name": "c3",
                                    "parentId": "#c"
                                }
                            }
                        },
                        "red2"
                    ]
                ],
                "createdIds": {
                    "x": "b",
                    "y": "c",
                    "z": "d"
                }
            }"##,
            1024,
            1024 * 1024,
        )
        .unwrap();

        let mut response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        let mut invocations = request.method_calls.into_iter();
        let mut call = invocations.next().unwrap();
        response.resolve_references(&mut call.method).unwrap();

        if let RequestMethod::Set(request) = call.method {
            let create = request
                .create
                .unwrap()
                .into_iter()
                .map(|(p, mut v)| (p, v.properties.remove(&Property::ParentId).unwrap()))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                create.get("a").unwrap(),
                &SetValue::Value(Value::Id(Id::new(1)))
            );
            assert_eq!(
                create.get("b").unwrap(),
                &SetValue::Value(Value::Id(Id::new(2)))
            );
            assert_eq!(
                create.get("c").unwrap(),
                &SetValue::Value(Value::Id(Id::new(3)))
            );
        } else {
            panic!("Expected Mailbox Set Request");
        }

        response.created_ids.insert("a".to_string(), Id::new(5));
        response.created_ids.insert("b".to_string(), Id::new(6));
        response.created_ids.insert("c".to_string(), Id::new(7));

        let mut call = invocations.next().unwrap();
        response.resolve_references(&mut call.method).unwrap();

        if let RequestMethod::Set(request) = call.method {
            let create = request
                .create
                .unwrap()
                .into_iter()
                .map(|(p, mut v)| (p, v.properties.remove(&Property::ParentId).unwrap()))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                create.get("a1").unwrap(),
                &SetValue::Value(Value::Id(Id::new(5)))
            );
            assert_eq!(
                create.get("b2").unwrap(),
                &SetValue::Value(Value::Id(Id::new(6)))
            );
            assert_eq!(
                create.get("c3").unwrap(),
                &SetValue::Value(Value::Id(Id::new(7)))
            );
        } else {
            panic!("Expected Mailbox Set Request");
        }
    }
}
