use std::collections::HashMap;

use crate::{
    error::{
        method::MethodError,
        request::{RequestError, RequestLimitError},
    },
    method::{
        changes::ChangesRequest,
        copy::{CopyBlobRequest, CopyRequest},
        get::GetRequest,
        import::ImportEmailRequest,
        parse::ParseEmailRequest,
        query::QueryRequest,
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::SetRequest,
        validate::ValidateSieveScriptRequest,
    },
    parser::{json::Parser, Error, Ignore, JsonObjectParser, Token},
    types::id::Id,
};

use super::{
    capability::Capability,
    echo::Echo,
    method::{MethodFunction, MethodName, MethodObject},
    Call, Request, RequestMethod,
};

impl Request {
    pub fn parse(json: &[u8], max_calls: usize, max_size: usize) -> Result<Self, RequestError> {
        if json.len() <= max_size {
            let mut request = Request {
                using: 0,
                method_calls: Vec::new(),
                created_ids: None,
            };
            let mut found_valid_keys = false;
            let mut parser = Parser::new(json);
            parser.next_token::<String>()?.assert(Token::DictStart)?;
            while let Some(key) = parser.next_dict_key::<u128>()? {
                match key {
                    0x0067_6e69_7375 => {
                        found_valid_keys = true;
                        parser.next_token::<Ignore>()?.assert(Token::ArrayStart)?;
                        loop {
                            match parser.next_token::<Capability>()? {
                                Token::String(capability) => {
                                    request.using |= capability as u32;
                                }
                                Token::Comma => (),
                                Token::ArrayEnd => break,
                                token => {
                                    return Err(token
                                        .error("capability", &token.to_string())
                                        .into())
                                }
                            }
                        }
                    }
                    0x0073_6c6c_6143_646f_6874_656d => {
                        found_valid_keys = true;

                        parser
                            .next_token::<Ignore>()?
                            .assert_jmap(Token::ArrayStart)?;
                        loop {
                            match parser.next_token::<Ignore>()? {
                                Token::ArrayStart => (),
                                Token::Comma => continue,
                                Token::ArrayEnd => break,
                                _ => {
                                    return Err(RequestError::not_request("Invalid JMAP request"));
                                }
                            };
                            if request.method_calls.len() < max_calls {
                                let method_name = match parser.next_token::<MethodName>() {
                                    Ok(Token::String(method)) => method,
                                    Ok(_) => {
                                        return Err(RequestError::not_request(
                                            "Invalid JMAP request",
                                        ));
                                    }
                                    Err(Error::Method(MethodError::InvalidArguments(_))) => {
                                        MethodName::error()
                                    }
                                    Err(err) => {
                                        return Err(err.into());
                                    }
                                };
                                parser.next_token::<Ignore>()?.assert_jmap(Token::Comma)?;
                                parser.ctx = method_name.obj;
                                let start_depth_array = parser.depth_array;
                                let start_depth_dict = parser.depth_dict;

                                let method = match (&method_name.fnc, &method_name.obj) {
                                    (MethodFunction::Get, _) => {
                                        if method_name.obj != MethodObject::SearchSnippet {
                                            GetRequest::parse(&mut parser).map(RequestMethod::Get)
                                        } else {
                                            GetSearchSnippetRequest::parse(&mut parser)
                                                .map(RequestMethod::SearchSnippet)
                                        }
                                    }
                                    (MethodFunction::Query, _) => {
                                        QueryRequest::parse(&mut parser).map(RequestMethod::Query)
                                    }
                                    (MethodFunction::Set, _) => {
                                        SetRequest::parse(&mut parser).map(RequestMethod::Set)
                                    }
                                    (MethodFunction::Changes, _) => {
                                        ChangesRequest::parse(&mut parser)
                                            .map(RequestMethod::Changes)
                                    }
                                    (MethodFunction::QueryChanges, _) => {
                                        QueryChangesRequest::parse(&mut parser)
                                            .map(RequestMethod::QueryChanges)
                                    }
                                    (MethodFunction::Copy, MethodObject::Email) => {
                                        CopyRequest::parse(&mut parser).map(RequestMethod::Copy)
                                    }
                                    (MethodFunction::Copy, MethodObject::Blob) => {
                                        CopyBlobRequest::parse(&mut parser)
                                            .map(RequestMethod::CopyBlob)
                                    }
                                    (MethodFunction::Import, MethodObject::Email) => {
                                        ImportEmailRequest::parse(&mut parser)
                                            .map(RequestMethod::ImportEmail)
                                    }
                                    (MethodFunction::Parse, MethodObject::Email) => {
                                        ParseEmailRequest::parse(&mut parser)
                                            .map(RequestMethod::ParseEmail)
                                    }
                                    (MethodFunction::Validate, MethodObject::SieveScript) => {
                                        ValidateSieveScriptRequest::parse(&mut parser)
                                            .map(RequestMethod::ValidateScript)
                                    }
                                    (MethodFunction::Echo, MethodObject::Core) => {
                                        Echo::parse(&mut parser).map(RequestMethod::Echo)
                                    }
                                    _ => Err(Error::Method(MethodError::UnknownMethod(
                                        method_name.to_string(),
                                    ))),
                                };

                                let method = match method {
                                    Ok(method) => method,
                                    Err(Error::Method(err)) => {
                                        parser.skip_token(start_depth_array, start_depth_dict)?;
                                        RequestMethod::Error(err)
                                    }
                                    Err(err) => {
                                        return Err(err.into());
                                    }
                                };

                                parser.next_token::<Ignore>()?.assert_jmap(Token::Comma)?;
                                let id = parser.next_token::<String>()?.unwrap_string("")?;
                                parser
                                    .next_token::<Ignore>()?
                                    .assert_jmap(Token::ArrayEnd)?;
                                request.method_calls.push(Call {
                                    id,
                                    method,
                                    name: method_name,
                                });
                            } else {
                                return Err(RequestError::limit(RequestLimitError::CallsIn));
                            }
                        }
                    }
                    0x7364_4964_6574_6165_7263 => {
                        found_valid_keys = true;
                        let mut created_ids = HashMap::new();
                        parser.next_token::<Ignore>()?.assert(Token::DictStart)?;
                        while let Some(key) = parser.next_dict_key::<String>()? {
                            created_ids.insert(
                                key,
                                parser.next_token::<Id>()?.unwrap_string("createdIds")?,
                            );
                        }
                        request.created_ids = Some(created_ids);
                    }
                    _ => {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                    }
                }
            }

            if found_valid_keys {
                Ok(request)
            } else {
                Err(RequestError::not_request("Invalid JMAP request"))
            }
        } else {
            Err(RequestError::limit(RequestLimitError::Size))
        }
    }
}

impl From<Error> for RequestError {
    fn from(value: Error) -> Self {
        match value {
            Error::Request(err) => err,
            Error::Method(err) => RequestError::not_request(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::request::Request;

    const TEST: &str = r#"
    {
        "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail" ],
        "methodCalls": [
          [ "method1", {
            "arg1": "arg1data",
            "arg2": "arg2data"
          }, "c1" ],
          [ "Core/echo", {
            "hello": true,
            "high": 5
          }, "c2" ],
          [ "method3", {"hello": [{"a": {"b": true}}]}, "c3" ]
        ],
        "createdIds": {
            "c1": "m1",
            "c2": "m2"
        }
      }
    "#;

    #[test]
    fn parse_request() {
        println!("{:?}", Request::parse(TEST.as_bytes(), 10, 1024));
    }
}
