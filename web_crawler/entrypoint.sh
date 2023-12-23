nohup celery -A celery_worker.celery:celery worker -l INFO -Q urls -n urls@%h --logfile=/celery_worker/celery_log/urls@%h.log --pool=threads --concurrency=50 --without-gossip --without-mingle &
celery -A celery_worker.celery:celery worker -l INFO -Q soup -n soup@%h --logfile=/celery_worker/celery_log/soup@%h.log --pool=threads --concurrency=100 --without-gossip --without-mingle
