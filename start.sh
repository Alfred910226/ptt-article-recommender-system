#!/bin/bash

# 設定 DEBUG 環境變數的值，可以根據需求修改
export TAG=14
export POSTGRES_PASSWORD=1234
export POSTGRES_USER=postgres
export POSTGRES_DB=postgres

# 指定 Docker Compose 配置文件的路徑
COMPOSE_FILE=docker-compose.yml

# 使用 Docker Compose 啟動服務
docker-compose -f $COMPOSE_FILE up -d