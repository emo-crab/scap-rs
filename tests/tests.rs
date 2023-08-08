#[cfg(test)]
mod tests {
  use std::str::FromStr;
  #[test]
  fn it_works() {
    let result = 2 + 2;
    let cvss = cvss::v3::CVSS::from_str("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
    println!("{cvss:?}");
    assert_eq!(result, 4);
  }
}
