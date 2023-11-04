from cassandra.cqlengine.models import Model
from cassandra.cqlengine import columns
import uuid


class User(Model):
    __keyspace__ = 'ptt'
    __table_name__ = 'users'

    id = columns.UUID(primary_key=True, default=uuid.uuid4)
    email = columns.Text(primary_key=True)
    password = columns.Text()
    created_at = columns.DateTime()
    is_verified = columns.Boolean(default=False)