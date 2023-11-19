import os

import redis

r = redis.Redis(
    host=os.getenv("REDIS_HOSTNAME"), 
    port=os.getenv("REDIS_PORT"), 
    db=0
)
