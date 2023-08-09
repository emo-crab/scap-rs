#[cfg(test)]
mod tests {
  use std::str::FromStr;
  #[test]
  fn it_works() {
    let result = 2 + 2;
    let cvss3 = cvss::v3::CVSS::from_str("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
    println!("{cvss3:?}");
    let cvss2 = cvss::v2::CVSS::from_str("CVSS:2.0/AV:L/AC:M/Au:N/C:C/I:C/A:C");
    println!("{cvss2:?}");
    assert_eq!(result, 4);
  }
}
