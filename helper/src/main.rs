use helper::{cpe_mode, cve_mode, cwe_mode, kb_mode, sync_mode, NVDHelper, TopLevel};

#[tokio::main]
async fn main() {
  let toplevel: TopLevel = argh::from_env();
  match toplevel.nested {
    NVDHelper::CVE(config) => cve_mode(config).await,
    NVDHelper::CPE(config) => cpe_mode(config).await,
    NVDHelper::CWE(config) => cwe_mode(config).await,
    NVDHelper::KB(config) => kb_mode(config).await,
    NVDHelper::SYNC(config) => sync_mode(config).await,
  };
}
