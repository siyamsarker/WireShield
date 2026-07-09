from fastapi.templating import Jinja2Templates
from fastapi import Request
from pathlib import Path

templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

def get_2fa_ui_html(client_id: str, request: Request):
    return templates.TemplateResponse(
        request=request,
        name="2fa_setup.html",
        context={"client_id": client_id},
    )

def get_2fa_verify_only_html(client_id: str, request: Request):
    return templates.TemplateResponse(
        request=request,
        name="2fa_verify.html",
        context={"client_id": client_id},
    )

def get_success_html(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="success.html",
    )

def get_access_denied_html(request: Request, reason: str = "vpn"):
    """403 gate page. `reason` picks the message + behaviour:
      - "vpn":     device isn't a recognized VPN peer (connectivity).
      - "portal":  no active session — sign in through the portal first.
      - "console": authenticated peer, but not cleared for the admin console.
    Unknown values fall back to "vpn" in the template.
    """
    return templates.TemplateResponse(
        request=request,
        name="access_denied.html",
        context={"reason": reason},
        status_code=403,
    )

def get_console_html(request: Request, csrf_token: str = ""):
    return templates.TemplateResponse(
        request=request,
        name="console.html",
        context={"csrf_token": csrf_token},
    )
