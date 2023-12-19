import os

USERNAME = os.getenv('RABBITMQ_USERNAME')
PASSWORD = os.getenv('RABBITMQ_PASSWORD')

broker_url = 'amqp://{}:{}@rabbitmq:5672/'.format(USERNAME, PASSWORD)
result_backend = 'rpc://{}:{}@rabbitmq:5672/'.format(USERNAME, PASSWORD)

imports = [
    'celery_worker.tasks.crawler'
]