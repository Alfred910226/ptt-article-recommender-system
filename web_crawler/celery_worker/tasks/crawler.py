import re
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from celery_worker.celery import celery
from celery_worker.schemas.crawler import ArticleData, CommentData
from celery_worker.kafka_connector import producer

BASE_URL = "https://www.ptt.cc/"

@celery.task
def crawl_next_page(url: str):

    page = web_request(url)

    soup = BeautifulSoup(page.content, 'html.parser')
    
    next_path = soup.find('a', class_='btn wide', string='‹ 上頁').get('href')
    if next_path:
        next_page_url = urljoin(BASE_URL, next_path)
        crawl_next_page.s(next_page_url).apply_async(queue='urls')
    else:
        print("There is no next page!")

    for div in soup.find_all("div", class_="r-ent"):
        try:
            path = div.find("div", class_="title").find('a', href=True).get('href')
        except Exception as e:
            print(e)
            print(div.get_text())

        article_url = urljoin(BASE_URL, path)
        crawl_article.s(article_url).apply_async(queue='urls')
    
    return None

@celery.task
def crawl_article(url: str):

    page = web_request(url)

    parse_out_article_comment.s(page.content).apply_async(queue='soup')
    parse_out_article_content.s(page.content).apply_async(queue='soup')

    return None

@celery.task
def parse_out_article_content(content: str):
    soup = BeautifulSoup(content, 'html.parser')

    article_id = parse_out_article_id(soup=soup)

    author = parse_out_author(soup=soup)

    board, title, created_at = parse_out_metaline(soup=soup)

    content = parse_out_content(soup=soup)

    category = parse_out_category(title=title)

    is_reply = parse_for_reply_status(title=title)

    text_pre_processing = content_preprocessing(content=content)

    result = ArticleData(
        article_id=article_id,
        author=author,
        title=title,
        content=content,
        board=board,
        is_reply=is_reply,
        created_at=created_at,
        text_pre_processing=text_pre_processing
    )
    data = result.model_dump_json()
    producer.produce(topic="articles", value=data)
    producer.flush()

    return None

@celery.task
def parse_out_article_comment(content: str):

    soup = BeautifulSoup(content, 'html.parser')

    article_id = parse_out_article_id(soup=soup)

    article_created_on = datetime.strptime(
        soup.find_all("span", class_="article-meta-value")[3].get_text(), 
        "%a %b %d %H:%M:%S %Y"
    )

    recent_datetime = None

    for div in soup.find_all("div", class_="push"):
        user_feedback = parse_out_user_feedback(div)
        user_id = parse_out_user_id(div)
        comment = parse_out_comment(div)
        ip_address = parse_out_ip_address(div)
        comment_created_at, recent_datetime = parse_out_comment_datetime(div, article_created_on, recent_datetime)
        try:
            result = CommentData(
                article_id=article_id,
                user_id=user_id,
                user_feedback=user_feedback,
                comment=comment,
                ip_address=ip_address,
                created_at=comment_created_at
            )
            data = result.model_dump_json()
            producer.produce(topic="comments", value=data)
            producer.flush()
        except Exception as e:
            print(e)
            print(article_id)

    return None

def web_request(url: str):
    cookie = {'over18':'1'}
    s = requests.session()
    s.keep_alive = False
    try:
        page = s.get(url, verify=True, cookies=cookie)
    except Exception as e:
        print(e)
    return page

def content_preprocessing(content):
    soup = BeautifulSoup(content, 'html.parser')
    content = soup.find("div", class_="bbs-screen bbs-content", id="main-content")
    for tag in content(['div', 'span', 'a']):
        tag.decompose()

    content = content.get_text().strip('\n')
    content = re.sub(r'\n+', '\n', content)
    content = re.sub(r'-(.*?)-', '', content, flags=re.DOTALL)
    return content


def parse_out_article_id(soup: BeautifulSoup):
    href = soup.find("link", rel="canonical").get('href')
    pattern = r"/([^/]+)\.html"
    match = re.search(pattern, href)
    if match:
        return match.group(1)

    return None

def parse_out_author(soup: BeautifulSoup):
    text = soup.find("span", class_="article-meta-value").get_text()
    author = re.search(r'(.+?)\s*\(', text)
    if author:
        return author.group(1)
        
    return None

def parse_out_metaline(soup: BeautifulSoup):
    content = soup.find("div", class_="bbs-screen bbs-content", id="main-content")
    try:
        board = content.find_all("span", class_="article-meta-value")[1].get_text()
        title = content.find_all("span", class_="article-meta-value")[2].get_text()
        created_at = datetime.strptime(
            content.find_all("span", class_="article-meta-value")[3].get_text(), 
            "%a %b %d %H:%M:%S %Y"
        )
    except Exception as e:
        print(e)
    
    return board, title, created_at

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

def parse_out_category(title: str):
    match = re.search(r"\[([^]]+)\]", title)

    if match:
        return match.group(1)

    return None

def parse_out_user_feedback(div):
    mapping_table = {
        "→ ": "newline",
        "推 ": "like",
        "噓 ": "unlike",
    }
    if div.find("span", class_="f1 hl push-tag"):
        user_feedback = div.find("span", class_="f1 hl push-tag").get_text()
    else:
        user_feedback = div.find("span", class_="hl push-tag").get_text()

    return mapping_table.get(user_feedback, "other")

def parse_out_user_id(div):
    user_id = div.find("span", class_="f3 hl push-userid").get_text()
    return user_id

def parse_out_comment(div):
    comment = div.find("span", class_="f3 push-content").get_text().replace(":", "").strip(' ') 
    return comment

def parse_out_ip_address(div):
    ipdatetime = div.find("span", class_="push-ipdatetime").get_text()
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, ipdatetime)
    
    if match:
        return match.group(0)

    return None

def parse_out_comment_datetime(div, article_created_on: datetime, recent_datetime: datetime):
    ipdatetime = div.find("span", class_="push-ipdatetime").get_text()

    date_pattern = r"\b\d{2}/\d{2}\b"
    date_match = re.search(date_pattern, ipdatetime)

    if date_match:
        date = f"{article_created_on.year}/{date_match.group(0)}"
    else:
        date = f"{article_created_on.year}/{article_created_on.month}/{article_created_on.day}"

    time_pattern = r"\b\d{2}:\d{2}\b"
    time_match = re.search(time_pattern, ipdatetime)

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
    elif comment_created_on > recent_datetime:
        recent_datetime = comment_created_on
    else:
        comment_created_on = comment_created_on.replace(year = comment_created_on.year + 1)
        recent_datetime = comment_created_on

    return comment_created_on, recent_datetime
