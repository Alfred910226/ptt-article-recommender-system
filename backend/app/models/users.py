from cassandra.cqlengine.models import Model
from cassandra.cqlengine import columns
import uuid


class User(Model):
    __keyspace__ = 'ptt'
    __table_name__ = 'users'

    uid = columns.UUID(primary_key=True, default=uuid.uuid4) 
    email = columns.Text(primary_key=True)
    password = columns.Text()
    created_at = columns.DateTime()
    is_verified = columns.Boolean(default=False)

class AuthenticatedVerificationEmailToken(Model):
    __keyspace__ = 'ptt'
    __table_name__ = 'authenticated_token'
    __options__ = {'default_time_to_live': 60}

    token = columns.Text(primary_key=True)
    uid = columns.UUID()
    created_at = columns.DateTime()
