use crate::error::Error;
use reqwest::{ClientBuilder, RequestBuilder};
use serde_json::Value::Object;

mod error;
mod v2;
const BASE_URL: &'static str = "https://services.nvd.nist.gov/rest/json/";
const VERSION: f32 = 2.0;
#[derive(Debug, Clone)]
pub struct NVDApi {
  base_path: String,
  client: reqwest::Client,
}

impl NVDApi {
  pub fn new(api_token: Option<String>) -> Result<Self, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    let mut auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_token}"))
      .map_err(|source| Error::InvalidApiToken { source })?;
    auth_value.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);
    let api_client = ClientBuilder::new()
      .default_headers(headers)
      .build()
      .map_err(|source| Error::ErrorBuildingClient { source })?;
    Ok(NVDApi {
      base_path: BASE_URL.to_owned(),
      client: api_client,
    })
  }
}

impl NVDApi {
  pub async fn request(&self, request: RequestBuilder) -> Result<Object, Error> {
    let request = request.build()?;
    let json = self
      .client
      .execute(request)
      .await
      .map_err(|source| Error::RequestFailed { source })?
      .text()
      .await
      .map_err(|source| Error::ResponseIoError { source })?;
    let result = serde_json::from_str(&json).map_err(|source| Error::JsonParseError { source })?;
    match result {
      Object::Error { error } => Err(Error::ApiError { error }),
      response => Ok(response),
    }
  }
}
