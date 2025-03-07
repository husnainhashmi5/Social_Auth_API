FROM python:3.12.2

# Set environment variables
ENV PYTHONBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=auth.settings
ENV PORT=80

WORKDIR /app

# Copy project files
COPY . /app/

# Install dependencies
RUN apt-get update
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy and set entrypoint
COPY entry.sh /app/entry.sh
RUN chmod +x /app/entry.sh

# Expose the port
EXPOSE ${PORT}

# Use the entrypoint script
ENTRYPOINT ["/app/entry.sh"]
