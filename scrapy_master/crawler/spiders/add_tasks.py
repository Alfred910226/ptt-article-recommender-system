import re
from datetime import datetime
from urllib.parse import urljoin

import scrapy

class AddTaskSpider(scrapy.Spider):
    name = 'add_task'
    start_urls = ['https://www.ptt.cc/bbs/Gossiping/index.html']

    custom_settings = {
        'ITEM_PIPELINES': {
            "crawler.pipelines.DistrubutedSpiderPipeline": 1,
        },
        'HTTPERROR_ALLOWED_CODES': [500, 520]
    }

    def __init__(self, *args, **kwargs):
        super(AddTaskSpider, self).__init__(*args, **kwargs)
        self.version = datetime.now().strftime("%Y%m%d%H%M")
        self.cookies={'over18':'1'}
        self.base_url = "https://www.ptt.cc/"

    def parse(self, response):
        
        if response.status != 200:
            self.logger.error("此頁面不存在: %s ", response.url)
            pattern = r'index(\d+)\.html'
            matched = re.search(pattern, response.url)
            if matched:
                index = int(matched.group(1))
                if index > 1:
                    index = index - 1
                    next_page_url = re.sub(pattern, r'index' + str(index) + r'.html', response.url)
                    yield scrapy.Request(url=next_page_url, callback=self.parse)

        elif response.xpath("//div[@class='btn-group btn-group-paging']/a[@class='btn wide disabled']/text()").get() != '‹ 上頁':
            next_path = response.xpath("//div[@class='btn-group btn-group-paging']/a[@class='btn wide'][text()='‹ 上頁']/@href").get()
            next_page_url = urljoin(self.base_url, next_path)
            yield scrapy.Request(url=next_page_url, callback=self.parse)

        for path in response.xpath("//div[@class='r-ent']/div[@class='title']/a/@href").getall():
            article_url = urljoin(self.base_url, path)
            task = {}
            task['url'] = article_url
            yield task

