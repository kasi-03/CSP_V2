"""
Application Entry Point for Voice-Based AI-Assisted Police Complaint Drafting System.

WSGI Server Entry Point:
- Exposes the Flask application instance 'app' for production WSGI servers (e.g., Gunicorn).
- Render Start Command: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120 --access-logfile - --error-logfile -

Local Development:
- Running 'python app.py' directly launches the development server on 127.0.0.1:5000.
- Production environments (FLASK_ENV=production or RENDER=true) strictly enforce debug=False.
"""

import os
from backend import create_app

# WSGI callable for Gunicorn and production servers
app = create_app()

if __name__ == "__main__":
    # Detect production environment
    is_production = (
        app.config.get("FLASK_ENV") == "production"
        or os.getenv("FLASK_ENV") == "production"
        or os.getenv("ENVIRONMENT") == "production"
        or os.getenv("RENDER", "").lower() in ("true", "1")
    )

    # In production, debug mode is strictly disabled; in local development, it can be enabled
    if is_production:
        debug_mode = False
        host = "0.0.0.0"
    else:
        # Default to True for interactive local development via python app.py, or respect FLASK_DEBUG
        debug_mode = os.getenv("FLASK_DEBUG", "true").lower() in ("true", "1")
        host = os.getenv("HOST", "127.0.0.1")

    # Dynamic port configuration via PORT environment variable (Render assigns $PORT)
    port = int(os.getenv("PORT", "5000"))

    app.run(debug=debug_mode, host=host, port=port)
