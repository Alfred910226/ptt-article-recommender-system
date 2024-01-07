# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import os
import socket
import json

import redis

from confluent_kafka import Producer
from crawler.items import ArticleItem, CommentItem

KAFKA_HOSTNAME = os.getenv('KAFKA_HOSTNAME')
KAFKA_PORT = os.getenv('KAFKA_PORT')

REDIS_HOSTNAME = os.getenv('REDIS_HOSTNAME')
REDIS_PORT = os.getenv('REDIS_PORT')
REDIS_DB = os.getenv('REDIS_DB')

class ArticlePipeline:
    def __init__(self):
        self.conf = {
            'bootstrap.servers': '{}:{}'.format(KAFKA_HOSTNAME, KAFKA_PORT), 
            'client.id': socket.gethostname()
        }
        self.producer = Producer(self.conf)

    def process_item(self, item, spider):
        if isinstance(item, ArticleItem):
            data = json.dumps(dict(item)).encode()
            self.producer.produce(topic="articles", value=data)
            self.producer.flush()

        return item
    
class CommentPipeline:
    def __init__(self):
        self.conf = {
            'bootstrap.servers': '{}:{}'.format(KAFKA_HOSTNAME, KAFKA_PORT), 
            'client.id': socket.gethostname()
        }
        self.producer = Producer(self.conf)

    def process_item(self, item, spider):
        if isinstance(item, CommentItem):
            data = json.dumps(dict(item)).encode()
            self.producer.produce(topic="comments", value=data)
            self.producer.flush()

        return item
    
class DistrubutedSpiderPipeline:
    def __init__(self):
        self.r = redis.StrictRedis(host=REDIS_HOSTNAME, port=REDIS_PORT, db=REDIS_DB)

    def process_item(self, item, spider):
        self.r.rpush('crawler:url', item['url'])
        return item


