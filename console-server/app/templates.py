from typing import Optional
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pathlib import Path

# Initialize templates
templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

def get_2fa_ui_html(client_id: str, request: Optional[Request] = None):
    """Render 2FA setup page using Jinja2 template."""
    if request is None:
        # Fallback for cases where request is not passed
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import URL
        request = StarletteRequest({"type": "http", "method": "GET", "url": URL("/")})
    
    return templates.TemplateResponse("2fa_setup.html", {
        "request": request,
        "client_id": client_id
    })

def get_2fa_verify_only_html(client_id: str, request: Optional[Request] = None):
    """Render 2FA verify-only page using Jinja2 template."""
    if request is None:
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import URL
        request = StarletteRequest({"type": "http", "method": "GET", "url": URL("/")})
    
    return templates.TemplateResponse("2fa_verify.html", {
        "request": request,
        "client_id": client_id
    })

def get_success_html(request: Optional[Request] = None):
    """Render success page using Jinja2 template."""
    if request is None:
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import URL
        request = StarletteRequest({"type": "http", "method": "GET", "url": URL("/success")})
    
    return templates.TemplateResponse("success.html", {
        "request": request
    })

def get_access_denied_html(request: Optional[Request] = None):
    """Render access denied page using Jinja2 template."""
    if request is None:
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import URL
        request = StarletteRequest({"type": "http", "method": "GET", "url": URL("/")})
    
    return templates.TemplateResponse("access_denied.html", {
        "request": request
    }, status_code=403)

def get_console_html(request: Optional[Request] = None):
    """Render console dashboard using Jinja2 template."""
    if request is None:
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import URL
        request = StarletteRequest({"type": "http", "method": "GET", "url": URL("/console")})
    
    return templates.TemplateResponse("console.html", {
        "request": request
    })
