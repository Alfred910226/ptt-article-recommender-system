import re
from datetime import datetime
from urllib.parse import urljoin

import requests
from lxml.html import fromstring
from bs4 import BeautifulSoup

from celery_worker.celery import celery
from celery_worker.schemas.crawler import ArticleData, CommentData

cookie = {'over18':'1'}
BASE_URL = "https://www.ptt.cc/"

@celery.task
def crawl_next_page(URL: str):
    s = requests.session()
    s.keep_alive = False
    page = s.get(URL, verify=False, cookies=cookie)
    soup = fromstring(page.text)
    path = soup.xpath("//div[@class='btn-group btn-group-paging']/a[@class='btn wide'][text()='‹ 上頁']/@href")
    if path:
        URL = urljoin(BASE_URL, path.pop())
        print(URL)
        crawl_directory.apply_async((URL, ), queue='web-crawler')
        crawl_next_page.apply_async((URL, ), queue='web-crawler')
    return None

@celery.task
def crawl_directory(URL: str):
    s = requests.session()
    s.keep_alive = False
    page = s.get(URL, verify=False, cookies=cookie)
    if page.status_code != 200:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            Error from crawl_directory:
            status_code: {page.status_code}
            directory link: {URL}
            ==================================================
            """
        )
    soup = BeautifulSoup(page.content, 'html.parser')
    
    for div_tag in soup.find_all("div", class_="title"):
        if not div_tag.find("a", href=True):
            continue

        article_url = div_tag.find("a", href=True).get("href")
        URL = urljoin(BASE_URL, article_url)
        # crawl_article.apply_async((URL, ), queue='web-crawler')
        crawl_comment.apply_async((URL, ), queue='web-crawler')

    return None

@celery.task
def crawl_article(URL: str):
    s = requests.session()
    s.keep_alive = False
    page = s.get(URL, verify=False, cookies=cookie)
    if page.status_code != 200:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            error from crawl_directory:
            status_code: {page.status_code}
            article link: {URL}
            ==================================================
            """
        )
    
    pattern = r"/Gossiping/(.*?)\.html"
    match = re.search(pattern, URL)

    if match:
        article_id = match.group(1)
    else:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            error from crawl_comment:
            Article id not found
            article link: {URL}
            ==================================================
            """
        )
    
    soup = BeautifulSoup(page.content, 'html.parser')
    contents = soup.find("div", class_="bbs-screen bbs-content", id="main-content")

    temp_author = contents.find_all("span", class_="article-meta-value")[0].get_text()
    author = temp_author.split(' ')[0]

    try:
        board = contents.find_all("span", class_="article-meta-value")[1].get_text()
    except:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            error from crawl_article:
            list index out of range
            article link: {URL}
            ==================================================
            """
        )
    title = contents.find_all("span", class_="article-meta-value")[2].get_text()

    match = re.match(r"^Re: (.*)", title)
    if match:
        is_reply = True
    else:
        is_reply = False

    match = re.search(r"\[([^]]+)\]", title)

    if match:
        temp_categories = match.group(1)
        categories = [temp_categories]
    else:
        categories = []

    created_on = datetime.strptime(
        contents.find_all("span", class_="article-meta-value")[3].get_text(), 
        "%a %b %d %H:%M:%S %Y"
    )
    """
    remove tags
    """
    for tag in contents(['div', 'span']):
        tag.decompose()

    for a_tag in contents.find_all("a", href=True):
        img_url = a_tag.get("href")
        img_tag = soup.new_tag("img", src=img_url)
        a_tag.replace_with(img_tag)

    content = contents.prettify().replace("\n", "<br>")

    response = dict(
        article_id=article_id,
        author=author,
        title=title,
        content=content,
        board=board,
        is_reply=is_reply,
        categories=categories,
        created_on=created_on
    )

    article_data = ArticleData(**response)
    print(article_data.model_dump_json())
    return None

@celery.task
def crawl_comment(URL: str):
    s = requests.session()
    s.keep_alive = False
    page = s.get(URL, verify=False, cookies=cookie)
    if page.status_code != 200:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            error from crawl_comment:
            status_code: {page.status_code}
            ==================================================
            """
        )
    pattern = r"/Gossiping/(.*?)\.html"
    match = re.search(pattern, URL)

    if match:
        article_id = match.group(1)
    else:
        print(
            f"""
            ==================== [ DEBUG ] ===================
            error from crawl_comment:
            Article id not found
            ==================================================
            """
        )

    soup = BeautifulSoup(page.content, 'html.parser')

    created_on = datetime.strptime(
        soup.find_all("span", class_="article-meta-value")[3].get_text(), 
        "%a %b %d %H:%M:%S %Y"
    )

    for div_tag in soup.find_all("div", class_="push"):

        if div_tag.find("span", class_="f1 hl push-tag"):
            user_reponse = div_tag.find("span", class_="f1 hl push-tag").get_text()
            
        elif div_tag.find("span", class_="hl push-tag"):
            user_reponse = div_tag.find("span", class_="hl push-tag").get_text()
        
        user_reponse_mapping_table = {
            "→ ": "newline",
            "推 ": "like",
            "噓 ": "unlike",
        }

        user_feedback = user_reponse_mapping_table.get(user_reponse, "other")

        user_id = div_tag.find("span", class_="f3 hl push-userid").get_text()
        comment = div_tag.find("span", class_="f3 push-content").get_text().replace(":", "")
        elements = div_tag.find("span", class_="push-ipdatetime").get_text()

        # 提取IP地址
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ip_match = re.search(ip_pattern, elements)
        
        if ip_match:
            ip_address = ip_match.group(0)
        else:
            ip_address = None
        
        # 提取日期
        date_pattern = r"\b\d{2}/\d{2}\b"
        date_match = re.search(date_pattern, elements)
        
        if date_match:
            date = date_match.group(0)
        else:
            date = f"{created_on.year}/{created_on.month}/{created_on.day}"

    
        str(created_on.year) + "/" + date

        # 提取時間
        time_pattern = r"\b\d{2}:\d{2}\b"
        time_match = re.search(time_pattern, elements)
        
        if time_match:
            time = time_match.group(0)
        else:
            time = "00:00"

        created_date = datetime.strptime(str(created_on.year) + "/" + date + " " + time, "%Y/%m/%d %H:%M")
        
        max_date = datetime(1971, 1, 1, 0, 0, 0)

        if created_date > max_date:
            max_date = created_date
            created_on = max_date
        else:
            created_on = created_date.replace(year = created_date.year + 1)

        response = dict(
            article_id=article_id,
            user_id=user_id,
            user_feedback=user_feedback,
            comment=comment,
            ip_address=ip_address,
            created_on=created_on
        )

        comment_data = CommentData(**response)
        print(comment_data.model_dump_json())
    return None