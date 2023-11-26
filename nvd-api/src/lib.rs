use crate::error::Error;
use crate::pagination::{ListResponse};
use reqwest::{ClientBuilder, RequestBuilder};

mod error;
pub mod pagination;
pub mod v2;

const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/";

#[derive(Debug, Clone)]
pub struct NVDApi {
  base_path: String,
  version: String,
  client: reqwest::Client,
}

impl NVDApi {
  pub fn new(api_token: Option<String>, version: &str) -> Result<Self, Error> {
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
    // println!("{}", json);
    let result = serde_json::from_str(&json).map_err(|source| Error::JsonParse { source })?;
    Ok(result)
  }
}
