from celery import Celery

celery=Celery('web-crawler')
celery.config_from_object('celery_worker.config')