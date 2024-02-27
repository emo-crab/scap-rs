create table nvd.knowledge_base
(
    id          binary(16)                          not null comment '知识库表ID'
        primary key,
    name        varchar(32)                         not null comment '关联cve的名称',
    description text                                not null comment '知识库描述',
    source      varchar(32)                         not null comment '来源',
    links       varchar(512)                        not null comment '路径',
    meta        json                                not null comment '元数据',
    created_at  timestamp default CURRENT_TIMESTAMP not null comment '创建时间',
    updated_at  timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '最后更新时间',
    constraint id_UNIQUE
        unique (id),
    constraint knowledge_base_UNIQUE
        unique (name, source, links),
    constraint kb_cve
        foreign key (name) references nvd.cves (id)
)
    comment '知识库表';

