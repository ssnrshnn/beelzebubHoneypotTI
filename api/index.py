"""
Vercel serverless function handler for Flask app
"""
import sys
import os

# Add parent directory to Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

def handler(request, start_response):
    """
    Vercel serverless function handler
    WSGI-compatible handler for Flask
    """
    return app(request.environ, start_response)
