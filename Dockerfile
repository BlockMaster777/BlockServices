FROM python:3.14
WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY bsrv /code/bs
CMD ["fastapi", "run", "bsrv/main.py", "--port", "8080"]
