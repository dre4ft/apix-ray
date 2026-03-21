#!/bin/bash
# Script to start APIX-Ray services

echo "🚀 Starting APIX-Ray services..."

# Start FastAPI server
echo "🌐 Starting FastAPI server on port 8080..."
python api.py &
API_PID=$!

# Start Flask web server
echo "🖥️  Starting Flask web server on port 8800..."
python web_serveur.py &
WEB_PID=$!

echo ""
echo "✅ All services started!"
echo "🌐 FastAPI: http://localhost:8080"
echo "🖥️  Web UI: http://localhost:8800"
echo ""
echo "Press Ctrl+C to stop all services"

# Function to kill all processes on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    kill $API_PID $WEB_PID 2>/dev/null
    echo "✅ All services stopped"
    exit 0
}

# Set trap to cleanup on exit
trap cleanup SIGINT SIGTERM

# Wait for all processes
wait