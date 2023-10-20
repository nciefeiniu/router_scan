# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CveSpiderItem(scrapy.Item):
    cve_id = scrapy.Field()
    cve_url = scrapy.Field()
    score = scrapy.Field()
    # 访问方式（远程、本地）
    access = scrapy.Field()
    # 复杂度
    complexity = scrapy.Field()
    # 认证系统
    authentication = scrapy.Field()
    # 机密性
    confidentiality = scrapy.Field()
    # 完整性
    integrity = scrapy.Field()
    # 可用性
    availability = scrapy.Field()
    # 描述
    description = scrapy.Field()

    vendor = scrapy.Field()
    product = scrapy.Field()
    version = scrapy.Field()


if __name__ == '__main__':
    _c = CveSpiderItem()
    print(_c.items())