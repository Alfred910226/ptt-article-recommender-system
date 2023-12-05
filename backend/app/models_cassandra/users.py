from datetime import datetime

from cassandra.cqlengine.models import Model
from cassandra.cqlengine import columns



class TokenRevoked(Model):
    __keyspace__ = 'article_express'
    __table_name__ = 'token_revoked'
    __options__ = {'default_time_to_live': 60}

    token = columns.Text(primary_key=True)
    uid = columns.UUID()
    created_at = columns.DateTime()

class EmailVerificationCode(Model):
    __keyspace__ = 'article_express'
    __table_name__ = 'email_verification_code'
    __options__ = {'default_time_to_live': 60 * 15}

    uid = columns.UUID(primary_key=True)
    code = columns.Text()

class EmailInProcess(Model):
    __keyspace__ = 'article_express'
    __table_name__ = 'email_in_process'
    __options__ = {'default_time_to_live': 60 * 10}

    task_source = columns.Text(primary_key=True)
    email = columns.Text(primary_key=True)
    created_at = columns.DateTime()