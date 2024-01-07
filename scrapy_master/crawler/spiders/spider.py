from datetime import datetime
import re
import os

from bs4 import BeautifulSoup
from scrapy_redis.spiders import RedisSpider

from crawler.items import ArticleItem, CommentItem

class PttSpider(RedisSpider):
    name = 'crawler'
    redis_key = 'crawler:url'

    custom_settings = {
        'SCHEDULER': 'scrapy_redis.scheduler.Scheduler',
        'DUPEFILTER_CLASS': 'scrapy_redis.dupefilter.RFPDupeFilter',
        'REDIS_URL': 'redis://{}:{}/{}'.format(os.getenv('REDIS_HOSTNAME'), os.getenv('REDIS_PORT'), os.getenv('REDIS_DB')),
        'ITEM_PIPELINES': {
            "crawler.pipelines.ArticlePipeline": 1,
            "crawler.pipelines.CommentPipeline": 1
        },
        'HTTPERROR_ALLOWED_CODES': [500, 520]
    }

    def __init__(self, *args, **kwargs):
        super(PttSpider, self).__init__(*args, **kwargs)
        self.version = datetime.now().strftime("%Y%m%d%H%M")
        self.cookies={'over18':'1'}
        self.base_url = "https://www.ptt.cc/"

    def parse(self, response):
        def parse_out_article_id(response):
            pattern = r"/([^/]+)\.html"
            match = re.search(pattern, response.url)
            if match:
                return match.group(1)
            return None
        
        def parse_out_author(response):
            text = response.xpath("//body/div[@id='main-container']/div[@id='main-content']/div[@class='article-metaline']/span[@class='article-meta-value']/text()").getall()[0]
            author = re.search(r'(.+?)\s*\(', text)
            if author:
                return author.group(1)
            return None
        
        def parse_out_board_name(response):
            board = response.xpath("//body/div[@id='main-container']/div[@id='main-content']/div[@class='article-metaline-right']/span[@class='article-meta-value']").get()
            return board
        
        def parse_out_title(response):
            titile = response.xpath("//body/div[@id='main-container']/div[@id='main-content']/div[@class='article-metaline']/span[@class='article-meta-value']/text()").getall()[1]
            return titile
        
        def parse_out_article_created_datetime(response):
            created_datetime = response.xpath("//body/div[@id='main-container']/div[@id='main-content']/div[@class='article-metaline'][3]/span[@class='article-meta-value']/text()").get()
            created_at = datetime.strptime(created_datetime, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d %H:%M:%S")
            return created_at
        
        def parse_out_content(soup: BeautifulSoup):
            content = soup.find("div", class_="bbs-screen bbs-content", id="main-content")

            for tag in content(['div', 'span']):
                tag.decompose()

            for a_tag in content.find_all("a", href=True):
                img_url = a_tag.get("href")
                img_tag = soup.new_tag("img", src=img_url)
                a_tag.replace_with(img_tag)

            return content.prettify().replace("\n", "<br>")

        def parse_for_reply_status(title: str):
            return title.startswith("Re:")
        
        def content_preprocessing(content):
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.find("div", class_="bbs-screen bbs-content", id="main-content")
            for tag in content(['div', 'span', 'a']):
                tag.decompose()

            content = content.get_text().strip('\n')
            content = re.sub(r'\n+', '\n', content)
            content = re.sub(r'-(.*?)-', '', content, flags=re.DOTALL).strip(' ')
            return content

        soup = BeautifulSoup(response.text, 'html.parser')

        article_id = parse_out_article_id(response=response)

        author = parse_out_author(response=response)

        board = parse_out_board_name(response)

        title = parse_out_title(response)

        article_created_at = parse_out_article_created_datetime(response)

        content = parse_out_content(soup=soup)

        is_reply = parse_for_reply_status(title=title)

        text_pre_processing = content_preprocessing(content=content)

        article_items = ArticleItem()
        article_items['version'] = self.version
        article_items['article_id'] = article_id
        article_items['url'] = response.url
        article_items['author'] = author
        article_items['title'] = title
        article_items['content'] = content
        article_items['board'] = board
        article_items['is_reply'] = is_reply
        article_items['created_at'] = article_created_at
        article_items['text_pre_processing'] = text_pre_processing
        
        yield article_items

        def parse_out_user_feedback(feedback):
            mapping_table = {
                "→ ": "newline",
                "推 ": "like",
                "噓 ": "unlike",
            }
            return mapping_table.get(feedback, "other")
        
        def parse_out_comment(content):
            reply_content = content.replace(":", "").strip(' ') 
            return reply_content
        
        def parse_out_ip_address(ip_and_datetime):
            pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            match = re.search(pattern, ip_and_datetime)
            
            if match:
                return match.group(0)

            return None

        def parse_out_comment_datetime(ip_and_datetime, article_created_at: datetime, recent_datetime: datetime):

            article_created_at = datetime.strptime(article_created_at, "%Y-%m-%d %H:%M:%S")

            date_pattern = r"\b\d{2}/\d{2}\b"
            date_match = re.search(date_pattern, ip_and_datetime)

            if date_match:
                date = f"{article_created_at.year}/{date_match.group(0)}"
            else:
                date = f"{article_created_at.year}/{article_created_at.month}/{article_created_at.day}"

            time_pattern = r"\b\d{2}:\d{2}\b"
            time_match = re.search(time_pattern, ip_and_datetime)

            if time_match:
                time = time_match.group(0)
            else:
                time = "00:00"

            comment_created_on = datetime.strptime(
                f"{date} {time}",
                "%Y/%m/%d %H:%M"
            )

            if recent_datetime is None:
                recent_datetime = comment_created_on
            elif comment_created_on >= recent_datetime:
                recent_datetime = comment_created_on
            else:
                comment_created_on = comment_created_on.replace(year = comment_created_on.year + 1)
                recent_datetime = comment_created_on

            comment_created_on_strftime = comment_created_on.strftime("%Y-%m-%d %H:%M:%S")
            return comment_created_on_strftime, recent_datetime

        comments = list()
        recent_datetime = None
        for index, comment in enumerate(response.xpath("//body/div[@id='main-container']/div[@id='main-content']/div[@class='push']")):
            user_id=comment.xpath("./span[@class='f3 hl push-userid']/text()").get()
            user_feedback=parse_out_user_feedback(comment.xpath("./span[@class='hl push-tag']/text()").get())
            reply_content=parse_out_comment(comment.xpath("./span[@class='f3 push-content']/text()").get())
            ip_address=parse_out_ip_address(comment.xpath("./span[@class='push-ipdatetime']/text()").get())
            comment_created_at, recent_datetime = parse_out_comment_datetime(
                ip_and_datetime=comment.xpath("./span[@class='push-ipdatetime']/text()").get(),
                article_created_at=article_created_at, 
                recent_datetime=recent_datetime
            )

            comments.append(dict(
                index=index,
                user_id=user_id,
                user_feedback=user_feedback,
                reply_content=reply_content,
                ip_address=ip_address,
                created_at=comment_created_at
            ))

        comment_items = CommentItem()
        comment_items['version'] = self.version
        comment_items['article_id'] = article_id
        comment_items['url'] = response.url
        comment_items['comments'] = comments

        yield comment_items
