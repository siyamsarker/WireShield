from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pathlib import Path

# Initialize templates
templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

def get_2fa_ui_html(client_id: str, request: Request):
    """Render 2FA setup page using Jinja2 template."""
    return templates.TemplateResponse("2fa_setup.html", {
        "request": request,
        "client_id": client_id
    })

def get_2fa_verify_only_html(client_id: str, request: Request):
    """Render 2FA verify-only page using Jinja2 template."""
    return templates.TemplateResponse("2fa_verify.html", {
        "request": request,
        "client_id": client_id
    })

def get_success_html(request: Request):
    """Render success page using Jinja2 template."""
    return templates.TemplateResponse("success.html", {
        "request": request
    })

def get_access_denied_html(request: Request):
    """Render access denied page using Jinja2 template."""
    return templates.TemplateResponse("access_denied.html", {
        "request": request
    }, status_code=403)

def get_console_html(request: Request, csrf_token: str = ""):
    """Render console dashboard using Jinja2 template."""
    return templates.TemplateResponse("console.html", {
        "request": request,
        "csrf_token": csrf_token,
    })
