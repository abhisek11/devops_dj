#!/bin/bash

python manage.py wait_for_db
python manage.py collectstatic --no-input
python manage.py makemigrations
python manage.py migrate
#gunicorn --bind 0.0.0.0:8000 app.wsgi:application
#python manage.py runserver 0.0.0.0:8000

exec "$@"
