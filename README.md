# CVE 路由漏洞 系统

## 建表语句

cve_data 表

```sql
create table cve_data
(
    id              bigint auto_increment,
    cve_id          varchar(255) null,
    cve_url         varchar(255) null,
    score           varchar(255) null,
    access          varchar(255) null,
    complexity      varchar(255) null,
    authentication  varchar(255) null,
    confidentiality varchar(255) null,
    integrity       varchar(255) null,
    availability    varchar(255) null,
    description     text         null,
    vendor          varchar(255) null,
    product         varchar(255) null,
    version         text null,
    snapshot_time         datetime null,
    constraint cve_data_pk
        primary key (id)
);

create unique index cve_data_cve_id_uindex
    on cve_data (cve_id);

```


## 启动爬虫

1. 去 `cve_spider/cve_spider/pipelines.py` 中修改数据库连接地址
2. 切换到 cve_spider 目录下
3. scrapy crawl cve_detail

