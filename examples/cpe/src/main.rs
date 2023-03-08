use std::fs::File;
use cpe::CpeAttributes;
use cpe::dictionary::CpeList;

fn verify_file_name(dir: String, name: String) -> String {
    std::fs::create_dir_all(format!("/home/kali-team/cpe/"));
    name
}

fn main() {
    let x = std::fs::read_to_string("/home/kali-team/IdeaProjects/nvd_rs/cpe.xml").unwrap();
    let c: CpeList = quick_xml::de::from_str(&x).unwrap();
    for cpe_item in c.cpe_item {
        let out = File::create(verify_file_name(cpe_item.cpe23_item.name.vendor.to_string(), cpe_item.cpe23_item.name.version.to_string())).expect("Failed to create file");
        serde_yaml::to_writer(out, &cpe_item).unwrap();
        println!("{}", serde_yaml::to_string(&cpe_item).unwrap());
    }
    // let wfn = "wfn:[part=a,vendor=foo!,product=ANY,version=ANY,update=ANY,edition=ANY,language=ANY,sw_edition=ANY,target_sw=ANY,target_hw=ANY,other=ANY]".to_owned();
    // let att = CpeAttributes::from_wfn(&wfn).unwrap();
    // println!("{}", att);
}
