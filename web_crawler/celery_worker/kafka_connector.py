import os
import socket

from confluent_kafka import Producer

KAFKA_HOSTNAME = os.getenv('KAFKA_HOSTNAME')
KAFKA_PORT = os.getenv('KAFKA_PORT')

conf = {'bootstrap.servers': '{}:{}'.format(KAFKA_HOSTNAME, KAFKA_PORT),
        'client.id': socket.gethostname()}

producer = Producer(conf)