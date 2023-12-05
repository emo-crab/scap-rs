#[cfg(test)]
mod tests {
  use nvd_api::pagination::ListResponse;

  #[test]
  fn cve() {
    let j = include_str!("test/CVE-2001-0328.json");
    let i: ListResponse = serde_json::from_str(j).unwrap();
    println!("{:?}", i);
    let j = include_str!("test/hasCertAlerts_2.0_fmt.json");
    let i: ListResponse = serde_json::from_str(j).unwrap();
    println!("{:?}", i);
  }
}
