FROM mcr.microsoft.com/cbl-mariner/base/python:3

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && pip3 install -r requirements.txt

COPY wiki_cacher.py wiki_cacher.py

CMD ["python3", "/app/wiki_cacher.py"]