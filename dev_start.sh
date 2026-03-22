#!/bin/bash
# Development script to start APIX-Ray services with auto-reload

echo "🚀 Starting APIX-Ray services in DEVELOPMENT MODE..."
echo "🔄 Auto-reload enabled for both API and Web UI"
echo ""

# Set environment variables for development
export API_RELOAD=true
export WEB_DEBUG=true

source .venv/bin/activate
# Start FastAPI server with auto-reload
echo "🌐 Starting FastAPI server on port 8080 (auto-reload enabled)..."
cd web_app && python3.12 api.py &
API_PID=$!

# Start Flask web server with debug mode
echo "🖥️  Starting Flask web server on port 8800 (debug mode enabled)..."
cd web_app && python3.12 web_serveur.py &
WEB_PID=$!

echo ""
echo "✅ All services started in development mode!"
echo "🌐 FastAPI: http://localhost:8080 (auto-reload)"
echo "🖥️  Web UI: http://localhost:8800 (debug mode)"
echo ""
echo "💡 The servers will automatically reload when you modify:"
echo "   - API code (web_app/api.py, web_app/apis/*.py)"
echo "   - Source code (src/*.py)"
echo "   - Playbooks (playbooks/*.py)"
echo "   - Web templates and static files"
echo ""
echo "Press Ctrl+C to stop all services"

# Function to kill all processes on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all development services..."
    kill $API_PID $WEB_PID 2>/dev/null
    echo "✅ All services stopped"
    exit 0
}

# Set trap to cleanup on exit
trap cleanup SIGINT SIGTERM

# Wait for all processes
wait