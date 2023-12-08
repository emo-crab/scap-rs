// cpe:2.3:a:file:file:3.33:*:*:*:*:*:*:*
#[cfg(test)]
mod tests {
  use std::str::FromStr;

  #[test]
  fn it_works() {
    let _result = 2 + 2;
    let cpe_test = nvd_cpe::CPEName::from_str("cpe:2.3:a:file:file:3.33:*:*:*:*:*:*:*").unwrap();
    println!("{cpe_test:?}");
  }
}
