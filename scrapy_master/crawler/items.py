# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy

class ArticleItem(scrapy.Item):
    version = scrapy.Field()
    article_id = scrapy.Field()
    url = scrapy.Field()
    author = scrapy.Field()
    title = scrapy.Field()
    content = scrapy.Field()
    board = scrapy.Field()
    is_reply = scrapy.Field()
    created_at = scrapy.Field()
    text_pre_processing = scrapy.Field()    

class CommentItem(scrapy.Item):
    version = scrapy.Field()
    article_id = scrapy.Field()
    url = scrapy.Field()
    comments = scrapy.Field()

class PageItem(scrapy.Item):
    version = scrapy.Field()
    page_url = scrapy.Field()

class TaskItem(scrapy.Item):
    url = scrapy.Field()

