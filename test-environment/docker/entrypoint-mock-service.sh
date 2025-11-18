#!/bin/sh

SERVICE_TYPE=${SERVICE_TYPE:-web}
SERVICE_PORT=${SERVICE_PORT:-8080}

echo "Starting mock service: $SERVICE_TYPE on port $SERVICE_PORT"

if [ "$SERVICE_TYPE" = "web" ]; then
    exec python3 /app/services/mock-web-server.py
elif [ "$SERVICE_TYPE" = "api" ]; then
    exec python3 /app/services/mock-api-service.py
else
    echo "Unknown service type: $SERVICE_TYPE"
    exit 1
fi
