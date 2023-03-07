use cpe::CpeAttributes;
use cpe::dictionary::CpeList;

fn main() {
    // let x = std::fs::read_to_string("/home/kali-team/IdeaProjects/nvd_rs/cpe.xml").unwrap();
    // let c: CpeList = quick_xml::de::from_str(&x).unwrap();
    // for cpe_item in c.cpe_item {
    //     println!("{}", cpe_item.name);
    //     // println!("{:?}", cpe_item.cpe23_item);
    //     let s = serde_yaml::to_string(&cpe_item.cpe23_item).unwrap();
    //     println!("{}", s);
    // }
    let wfn = "wfn:[part=a,vendor=foo!,product=ANY,version=ANY,update=ANY,edition=ANY,language=ANY,sw_edition=ANY,target_sw=ANY,target_hw=ANY,other=ANY]".to_owned();
    let att = CpeAttributes::from_wfn(&wfn).unwrap();
    println!("{}", att);
}
