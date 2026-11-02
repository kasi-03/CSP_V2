"""
WSGI Entry Point for Production Deployment (SEC-06).

Exposes the production Flask application callable for Gunicorn and other WSGI servers.
Render Start Command:
    gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120 --access-logfile - --error-logfile -
"""

from app import app

if __name__ == "__main__":
    app.run()

