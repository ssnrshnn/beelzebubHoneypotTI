#!/bin/bash
# Start Beelzebub Dashboard

echo "======================================"
echo "  Beelzebub Honeypot Dashboard"
echo "======================================"
echo ""

# Check if logs directory exists and has log files
if [ ! -d "logs" ]; then
    echo "❌ Error: logs/ directory not found"
    echo "Please ensure the logs directory exists before starting the dashboard."
    exit 1
fi

# Check if there are any .log files in logs directory
if [ -z "$(find logs -name '*.log' -type f 2>/dev/null)" ]; then
    echo "⚠️  Warning: No .log files found in logs/ directory"
    echo "The dashboard will start but may not display any data."
    echo ""
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Check if dependencies are installed
echo "📦 Checking dependencies..."
if ! python3 -c "import flask" 2>/dev/null; then
    echo "⚠️  Flask not found. Installing dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        exit 1
    fi
fi

echo "✅ Dependencies OK"
echo ""

# Start the dashboard
echo "🚀 Starting dashboard..."
echo ""
echo "Dashboard will be available at:"
echo "  - Local:   http://localhost:5000"
echo "  - Network: http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "======================================"
echo ""

python3 app.py

