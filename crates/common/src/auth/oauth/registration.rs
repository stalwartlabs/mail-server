/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<ApplicationType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>, // Using serde_json::Value for flexibility

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<SubjectType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub default_acr_values: Vec<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<CompactString>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub request_uris: Vec<CompactString>,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub additional_fields: HashMap<CompactString, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationResponse {
    // Required fields
    pub client_id: CompactString,

    // Optional fields specific to the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<CompactString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<CompactString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<CompactString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,

    // Echo back the request
    #[serde(flatten)]
    pub request: ClientRegistrationRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Pairwise,
    Public,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
}
