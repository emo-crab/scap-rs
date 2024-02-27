create table nvd.cve_product
(
    cve_id     varchar(16) not null comment 'CVE编号',
    product_id binary(16)  not null comment '产品ID',
    primary key (cve_id, product_id),
    constraint cve_id
        foreign key (cve_id) references nvd.cves (id),
    constraint product_id
        foreign key (product_id) references nvd.products (id)
)
    comment 'cve_match表';

create index product_id_idx
    on nvd.cve_product (product_id);

