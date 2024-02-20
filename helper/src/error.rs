pub type HelperResult<T> = Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("Error AKBApi: {}", source)]
  AKBApi {
    #[from]
    source: attackerkb_api_rs::error::Error,
  },
}
