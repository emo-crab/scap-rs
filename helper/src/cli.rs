use argh::FromArgs;
use std::path::PathBuf;

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "NVDHelper")]
pub struct TopLevel {
  #[argh(subcommand)]
  pub nested: NVDHelper,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
pub enum NVDHelper {
  CVE(CVECommand),
  CPE(CPECommand),
  EXP(EXPCommand),
  Sync(SyncCommand),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "cve helper")]
#[argh(subcommand, name = "cve")]
pub struct CVECommand {
  #[argh(
    option,
    description = "import cve from json.gz. like/nvdcve-1.1-2023.json.gz"
  )]
  pub path: Option<PathBuf>,
  #[argh(switch, description = "update cve from nvd api")]
  pub api: bool,
  #[argh(option, description = "update cve from nvd api N hours ago until now")]
  pub hours: Option<i64>,
  #[argh(option, description = "update cve from nvd api by id")]
  pub id: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "cpe helper")]
#[argh(subcommand, name = "cpe")]
pub struct CPECommand {
  #[argh(
    option,
    description = "import cpe from xml.gz. official-cpe-dictionary_v2.3.xml.gz"
  )]
  pub path: Option<PathBuf>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "exp helper")]
#[argh(subcommand, name = "exp")]
pub struct EXPCommand {
  #[argh(option, description = "import exp from files_exploits.csv")]
  pub path: Option<PathBuf>,
  #[argh(option, description = "import exp from nuclei-templates path")]
  pub template: Option<PathBuf>,
  #[argh(switch, description = "update exp from nuclei-templates")]
  pub api: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "sync helper")]
#[argh(subcommand, name = "sync")]
pub struct SyncCommand {
  #[argh(switch, description = "sync exp")]
  pub exp: bool,
  #[argh(switch, description = "sync cve")]
  pub cve: bool,
}
