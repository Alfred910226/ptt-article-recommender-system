from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

class ArticleData(BaseModel):
    article_id: str
    author: str
    title: str
    content: str
    board: str
    is_reply: bool
    created_at: datetime
    text_pre_processing: str

class CommentData(BaseModel):
    article_id: str
    user_id: str
    user_feedback: str
    comment: str
    ip_address: Optional[str] = None
    created_at: datetime
