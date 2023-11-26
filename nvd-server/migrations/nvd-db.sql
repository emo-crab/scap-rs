-- MySQL Script generated by MySQL Workbench
-- 2023年09月17日 星期日 17时30分23秒
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema nvd
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema nvd
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `nvd` ;
USE `nvd` ;

-- -----------------------------------------------------
-- Table `nvd`.`vendors`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nvd`.`vendors` (
  `id` BINARY(16) NOT NULL COMMENT '供应商ID',
  `official` TINYINT ZEROFILL NOT NULL DEFAULT 0 COMMENT '是否为官方数据',
  `name` VARCHAR(128) NOT NULL COMMENT '供应商名字',
  `description` TEXT NULL COMMENT '供应商描述',
  `homepage` VARCHAR(256) NULL COMMENT '供应商主页',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) VISIBLE,
  UNIQUE INDEX `id_UNIQUE` USING BTREE (`id`) VISIBLE)
ENGINE = InnoDB
COMMENT = '供应商表';


-- -----------------------------------------------------
-- Table `nvd`.`products`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nvd`.`products` (
  `id` BINARY(16) NOT NULL COMMENT '产品ID',
  `vendor_id` BINARY(16) NOT NULL COMMENT '提供商外键',
  `official` TINYINT ZEROFILL NOT NULL DEFAULT 0 COMMENT '是否为官方数据',
  `part` CHAR(1) NOT NULL DEFAULT '*' COMMENT '硬件设备 h,操作系统 o,应用程序 a',
  `name` VARCHAR(128) NOT NULL COMMENT '产品名字',
  `description` TEXT NULL COMMENT '产品描述',
  `homepage` VARCHAR(256) NULL COMMENT '供应商主页',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间',
  PRIMARY KEY (`id`),
  INDEX `vendor_idx` (`vendor_id` ASC) VISIBLE,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `name_UNIQUE` USING BTREE (`vendor_id`, `name`) VISIBLE,
  CONSTRAINT `product_vendor`
    FOREIGN KEY (`vendor_id`)
    REFERENCES `nvd`.`vendors` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB
COMMENT = '产品表';


-- -----------------------------------------------------
-- Table `nvd`.`cves`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nvd`.`cves` (
  `id` VARCHAR(32) NOT NULL COMMENT 'CVE编号',
  `year` INT(4) NOT NULL DEFAULT 0 COMMENT 'cve年份',
  `assigner` VARCHAR(64) NOT NULL COMMENT '分配者',
  `references` JSON NOT NULL COMMENT '参考链接',
  `description` JSON NOT NULL COMMENT '描述',
  `problem_type` JSON NOT NULL COMMENT '通用弱点枚举',
  `cvss3_vector` VARCHAR(64) NOT NULL COMMENT '通用漏洞评分系统',
  `cvss3_score` FLOAT NOT NULL DEFAULT 0.0 COMMENT 'cvss3评分',
  `cvss2_vector` VARCHAR(64) NOT NULL COMMENT '通用漏洞评分系统',
  `cvss2_score` FLOAT NOT NULL DEFAULT 0.0 COMMENT 'cvss2评分',
  `configurations` JSON NOT NULL COMMENT 'cpe匹配',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` USING BTREE (`id`) VISIBLE,
  INDEX `year_idx` (`year` ASC) VISIBLE)
ENGINE = InnoDB
COMMENT = 'CVE表';


-- -----------------------------------------------------
-- Table `nvd`.`cwes`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nvd`.`cwes` (
  `id` INT NOT NULL COMMENT 'CWE ID',
  `name` VARCHAR(256) NOT NULL COMMENT 'CWE 名称',
  `description` TEXT NOT NULL COMMENT 'CWE描述',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) VISIBLE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `nvd`.`cve_product`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nvd`.`cve_product` (
  `cve_id` VARCHAR(16) NOT NULL,
  `product_id` BINARY(16) NOT NULL,
  PRIMARY KEY (`cve_id`, `product_id`),
  INDEX `product_id_idx` (`product_id` ASC) VISIBLE,
  CONSTRAINT `cve_id`
    FOREIGN KEY (`cve_id`)
    REFERENCES `nvd`.`cves` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `product_id`
    FOREIGN KEY (`product_id`)
    REFERENCES `nvd`.`products` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
COMMENT = 'cve_match表';


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;