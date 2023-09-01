// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub enum Version {
    V1,
    V2,
    V3,
    V4,
    V5,
}

#[async_trait]
impl<S> FromRequestParts<S> for Version
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let params: Path<HashMap<String, String>> =
            parts.extract().await.map_err(IntoResponse::into_response)?;

        let version = params.get("version").ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "code": 404,
                    "message": "version param missing",
                })),
            )
                .into_response()
        })?;

        match version.as_str() {
            "v1" => Ok(Version::V1),
            "v2" => Ok(Version::V2),
            "v3" => Ok(Version::V3),
            "v4" => Ok(Version::V4),
            "v5" => Ok(Version::V5),
            _ => Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "code": 404,
                    "message": "unknown version",
                })),
            )
                .into_response()),
        }
    }
}
