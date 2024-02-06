create table cves
(
    id             varchar(32)                         not null comment 'CVE编号'
        primary key,
    year           int(4)    default 0                 not null comment 'cve年份',
    assigner       varchar(64)                         not null comment '分配者',
    description    json                                not null comment '描述',
    severity       varchar(32)                         not null comment '严重等级',
    metrics        json                                not null comment '通用漏洞评分系统',
    weaknesses     json                                not null comment '通用弱点枚举',
    configurations json                                not null comment 'cpe匹配',
    `references`   json                                not null comment '参考链接',
    created_at     timestamp default CURRENT_TIMESTAMP not null comment '创建时间',
    updated_at     timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '最后更新时间',
    constraint id_UNIQUE
        unique (id)
)
    comment 'CVE表';

create index year_idx
    on cves (year);

