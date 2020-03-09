FROM python:3-alpine
MAINTAINER Hleb Rubanau <contact@rubanau.com>

RUN apk add --update git build-base libffi-dev
ADD requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

EXPOSE 8000
WORKDIR /app
#RUN touch /app/__init__.py 
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8000 --workers=3 --access-logfile - --error-logfile - --log-level debug" PYTHONUNBUFFERED=1
ENTRYPOINT ["gunicorn"]
CMD ["auth:app"]
COPY auth.py /app/


