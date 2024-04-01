use std::path::PathBuf;

use argh::FromArgs;

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
  CWE(CWECommand),
  CPE(CPECommand),
  KB(KBCommand),
  SYNC(SyncCommand),
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
  #[argh(switch, description = "update cve from cnnvd api")]
  pub cnnvd_api: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "cwe helper")]
#[argh(subcommand, name = "cwe")]
pub struct CWECommand {
  #[argh(option, description = "import cwe from xml.zip. cwec_latest.xml.zip")]
  pub path: Option<PathBuf>,
  #[argh(option, description = "import cwe from json. cwe.json")]
  pub json: Option<PathBuf>,
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
#[argh(description = "kb helper")]
#[argh(subcommand, name = "kb")]
pub struct KBCommand {
  #[argh(option, description = "import kb from files_exploits.csv")]
  pub path: Option<PathBuf>,
  #[argh(option, description = "import kb from nuclei-templates path")]
  pub template: Option<PathBuf>,
  #[argh(switch, description = "update kb from nuclei-templates")]
  pub api: bool,
  #[argh(switch, description = "import knowledge-base from attackerkb api")]
  pub akb: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "sync helper")]
#[argh(subcommand, name = "sync")]
pub struct SyncCommand {
  #[argh(switch, description = "sync kb")]
  pub kb: bool,
  #[argh(switch, description = "sync cve")]
  pub cve: bool,
}
