use helper::{cpe_mode, cve_mode, NVDHelper, TopLevel};

#[tokio::main]
async fn main() {
  let toplevel: TopLevel = argh::from_env();
  match toplevel.nested {
    NVDHelper::CVE(cve_config) => cve_mode(cve_config).await,
    NVDHelper::CPE(cpe_config) => cpe_mode(cpe_config),
  };
}
