FROM python:3.10

RUN pip install --upgrade pip
RUN apt-get update && apt-get install -y \
	tini

COPY ./requirements.txt .
COPY ./entrypoint.sh .
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]