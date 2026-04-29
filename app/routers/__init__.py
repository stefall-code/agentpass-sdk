from app.routers.auth import auth_router
from app.routers.agents import agent_router
from app.routers.admin import admin_router
from app.routers.resources import resource_router
from app.routers.websocket import ws_router

__all__ = ["auth_router", "agent_router", "admin_router", "resource_router", "ws_router"]
