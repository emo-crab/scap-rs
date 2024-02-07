use helper::{cpe_mode, cve_mode, exploit_mode, NVDHelper, TopLevel};

#[tokio::main]
async fn main() {
  let toplevel: TopLevel = argh::from_env();
  match toplevel.nested {
    NVDHelper::CVE(config) => cve_mode(config).await,
    NVDHelper::CPE(config) => cpe_mode(config).await,
    NVDHelper::EXP(config) => exploit_mode(config).await,
  };
}
