pub mod cnnvd;
pub mod cnvd;
pub mod error;

// https://www.cnnvd.org.cn/static/download/CNNVD_XML_Specification.pdf
// CNNVD的XML一点都不标准，都没有转义，解析会报错。所以使用CNVD的XML

pub fn add(left: usize, right: usize) -> usize {
  left + right
}

#[cfg(test)]
mod tests {
  use super::*;
  

  #[test]
  fn it_works() {
    let result = add(2, 2);
    assert_eq!(result, 4);
  }
}
