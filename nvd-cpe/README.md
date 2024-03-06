# CPE 通用平台枚举

[![github]](https://github.com/emo-crab/scap-rs/tree/main/nvd-cpe)
[![crates-io]](https://crates.io/crates/nvd-cpe)
[![docs-rs]](crate)

[github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
[docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs

## 介绍
> CPE (Common Platform Enumeration)，通用平台枚举 （CPE） 是信息技术系统、软件和包的结构化命名方案。基于统一资源标识符（URI）的通用语法，CPE包括正式名称格式，根据系统检查名称的方法以及将文本和测试绑定到名称的描述格式。

## 格式
- CPE 2.3 遵循以下格式，由 NIST 维护：
```text
cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
```
- 例如：
```text
cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*
```
### CPE版本: cpe_version
- 目前最新为2.3

### 属性

- 剩下的分为11个属性
```rust
pub struct CPEName {
  // 分类：a，o，h
  pub part: Part,
  // 创建产品个人或者组织/厂商
  pub vendor: Component,
  // 产品标题或者名称
  pub product: Component,
  // 由厂商提供用来表示产品的特定的发行版本
  pub version: Component,
  // 同样是厂商提供表示产品的更新版本，比version范围更小
  pub update: Component,
  // 这个属性同样表示版本，属于被弃用的属性，一般是为了兼容更早CPE版本，默认值为ANY
  pub edition: Component,
  // 表示产品在操作界面所支持的语言
  pub language: Language,
  // 表示产品是针对某些特定市场或类别的目标用户
  pub sw_edition: Component,
  // 产品运行需要的软件环境
  pub target_sw: Component,
  // 产品运行需要的硬件环境
  pub target_hw: Component,
  // 表示无法归类上上述其他属性的值
  pub other: Component,
}
```