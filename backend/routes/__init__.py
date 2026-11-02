"""
Routes package initializer.
Exports all blueprints for dashboard, complaints, and settings.
"""

from .dashboard import dashboard_bp
from .complaints import complaints_bp
from .settings import settings_bp
from .auth import auth_bp
from .admin import admin_bp

__all__ = ["dashboard_bp", "complaints_bp", "settings_bp", "auth_bp", "admin_bp"]
