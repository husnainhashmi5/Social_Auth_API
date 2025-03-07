#!/bin/sh

# Run database migrations
python manage.py migrate --noinput

# Collect static files (uncomment if needed)
# python manage.py collectstatic --noinput

# Start Gunicorn with correct settings
exec gunicorn auth.wsgi:application --bind 0.0.0.0:$PORT
