#!/bin/bash
# Start Beelzebub Dashboard

echo "======================================"
echo "  Beelzebub Honeypot Dashboard"
echo "======================================"
echo ""

# Check if beelzebub.log exists
if [ ! -f "beelzebub.log" ]; then
    echo "❌ Error: beelzebub.log not found in current directory"
    echo "Please ensure the log file is present before starting the dashboard."
    exit 1
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

