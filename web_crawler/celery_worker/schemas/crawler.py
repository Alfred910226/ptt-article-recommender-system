from datetime import datetime
from typing import List

from pydantic import BaseModel

class ArticleData(BaseModel):
    article_id: str
    author: str
    title: str
    content: str
    board: str
    is_reply: bool
    categories: List
    created_on: datetime

class CommentData(BaseModel):
    article_id: str
    user_id: str
    user_feedback: str
    comment: str
    ip_address: str
    created_on: datetime
