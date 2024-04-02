pub type HelperResult<T> = Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("Error AKBApi: {}", source)]
  AKBApi {
    #[from]
    source: attackerkb_api_rs::error::Error,
  },
  #[error("Error CNNVDApi: {}", source)]
  CNNVDApi {
    #[from]
    source: cnvd::error::Error,
  },
}
