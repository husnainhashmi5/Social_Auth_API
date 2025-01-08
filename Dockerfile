# Use an official Python image as a base
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose a port (if needed)
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
