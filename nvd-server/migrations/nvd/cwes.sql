create table nvd.cwes
(
    id          int                                 not null comment 'CWE ID'
        primary key,
    name        varchar(256)                        not null comment 'CWE 名称',
    description text                                not null comment 'CWE描述',
    created_at  timestamp default CURRENT_TIMESTAMP not null comment '创建时间',
    updated_at  timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '最后更新时间',
    constraint id_UNIQUE
        unique (id),
    constraint name_UNIQUE
        unique (name)
)
    comment '弱点枚举';

