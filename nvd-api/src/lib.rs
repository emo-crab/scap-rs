//! [![github]](https://github.com/emo-crab/scap-rs)&ensp;[![crates-io]](https://crates.io/crates/nvd-api)&ensp;[![docs-rs]](crate)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
use std::fmt::Display;

use reqwest::{ClientBuilder, RequestBuilder};

use crate::error::Error;
use crate::pagination::ListResponse;

pub mod error;
pub mod pagination;
pub mod v2;

const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/";

#[derive(Debug, Clone)]
pub struct NVDApi {
  base_path: String,
  version: String,
  client: reqwest::Client,
}

pub enum ApiVersion {
  V2_0,
}

impl Default for ApiVersion {
  fn default() -> Self {
    Self::V2_0
  }
}

impl Display for ApiVersion {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        ApiVersion::V2_0 => String::from("2.0"),
      }
    )
  }
}

impl NVDApi {
  pub fn new(api_token: Option<String>, version: ApiVersion) -> Result<Self, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(api_token) = api_token {
      let mut auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_token}"))
        .map_err(|source| Error::InvalidApiToken { source })?;
      auth_value.set_sensitive(true);
      headers.insert(reqwest::header::AUTHORIZATION, auth_value);
    }
    let api_client = ClientBuilder::new()
      .default_headers(headers)
      .build()
      .map_err(|source| Error::BuildingClient { source })?;
    Ok(NVDApi {
      base_path: BASE_URL.to_owned(),
      version: version.to_string(),
      client: api_client,
    })
  }
}

impl NVDApi {
  pub async fn request(&self, request: RequestBuilder) -> Result<ListResponse, Error> {
    let request = request.build()?;
    let json = self
      .client
      .execute(request)
      .await
      .map_err(|source| Error::RequestFailed { source })?
      .text()
      .await
      .map_err(|source| Error::ResponseIo { source })?;
    let result = serde_json::from_str(&json).map_err(|source| Error::JsonParse { source })?;
    Ok(result)
  }
}
