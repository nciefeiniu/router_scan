# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter

import pymysql
import traceback

from datetime import datetime


class CveSpiderPipeline:
    def __init__(self):
        self.conn = pymysql.connect(host='127.0.0.1', user='root', password='123456',
                                    database='test5')
        self.cursor = self.conn.cursor()

    def process_item(self, item, spider):
        try:
            self.cursor.execute("""INSERT INTO cve_data (cve_id, cve_url, score, access, complexity, authentication, confidentiality, integrity, availability, description, vendor, product, version, snapshot_time)  
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                                (item['cve_id'], item['cve_url'], item['score'], item['access'], item['complexity'],
                                 item['authentication'], item['confidentiality'], item['integrity'], item['availability'], item['description'],
                                 item['vendor'], item['product'], item['version'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            self.conn.commit()
        except pymysql.err.IntegrityError:
            self.conn.rollback()
        except Exception as e:
            print(traceback.format_exc())
            self.conn.rollback()
        return item
