import os

RABBITMQ_USERNAME = os.getenv('RABBITMQ_USERNAME')
RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD')
RABBITMQ_HOSTNAME = os.getenv('RABBITMQ_HOSTNAME')
RABBITMQ_PORT = os.getenv('RABBITMQ_PORT')

broker_url = 'amqp://{}:{}@{}:{}/'.format(RABBITMQ_USERNAME, RABBITMQ_PASSWORD, RABBITMQ_HOSTNAME, RABBITMQ_PORT)
result_backend = 'rpc://'
task_serializer = 'json'
result_serializer = 'json'
database_table_schemas = {
    'task': 'public',
    'group': 'public'
}
database_table_names = {
    'task': 'crawler_task',
    'group': 'crawler_group'
}
imports = [
    'celery_worker.tasks.crawler'
]