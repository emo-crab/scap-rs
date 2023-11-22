use reqwest::{ClientBuilder, RequestBuilder};
use crate::error::Error;

mod v2;
mod error;

#[derive(Debug, Clone)]
pub struct NVDApi {
  base_path: String,
  client: reqwest::Client,
}

impl NVDApi {
  pub fn new(api_token: String) -> Result<Self, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
      "Notion-Version",
      reqwest::header::HeaderValue::from_static(NOTION_API_VERSION),
    );
    let mut auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_token}"))
        .map_err(|source| Error::InvalidApiToken { source })?;
    auth_value.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);
    let api_client = ClientBuilder::new()
        .default_headers(headers)
        .build()
        .map_err(|source| Error::ErrorBuildingClient { source })?;
    Ok(NVDApi {
      base_path: "https://api.notion.com/v1".to_owned(),
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
    let result =
        serde_json::from_str(&json).map_err(|source| Error::JsonParseError { source })?;
    match result {
      Object::Error { error } => Err(Error::ApiError { error }),
      response => Ok(response),
    }
  }
}