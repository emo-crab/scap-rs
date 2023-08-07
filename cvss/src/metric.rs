use std::fmt::{Debug, Display};
use std::str::FromStr;

pub trait Metric: Clone + Debug + FromStr + Display {
  const NAME: &'static str;
  fn score(&self) -> f32;
  fn as_str(&self) -> &'static str;
}
