"""Member management (admin only; the executor / AI path has no route here)."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from adapters.members import ROLES, MemberError
from web.auth import Guards
from web.context import AppContext

MEMBER_ERRORS = {
    "invalid": (400, "Correo o rol inválido."),
    "exists": (409, "Esa persona ya es miembro."),
    "not_found": (404, "Esa persona no es miembro."),
    "last_admin": (409, "No se puede quitar ni degradar al último administrador."),
    "self": (409, "No puedes cambiar tu propio rol ni quitarte a ti mismo."),
    "unavailable": (503, "No se pudo guardar el cambio: base de datos no disponible."),
}


def _member_error(exc: MemberError) -> JSONResponse:
    status, message = MEMBER_ERRORS[exc.code]
    return JSONResponse({"error": message, "code": exc.code}, status_code=status)


class MemberIn(BaseModel):
    email: str
    role: str


class RoleIn(BaseModel):
    role: str


def register(router: FastAPI, ctx: AppContext, guards: Guards) -> None:
    """Add these routes straight onto the app (keeps `app.routes` flat)."""

    @router.get("/api/members")
    def list_members(request: Request) -> JSONResponse:
        """Admins only: the team list is access-control data, viewers do not need it."""
        _, denied = guards.admin_gate(request, write=False)
        if denied:
            return denied
        try:
            return JSONResponse({"members": ctx.members.list(), "roles": list(ROLES)},
                                headers={"Cache-Control": "no-store"})
        except MemberError as exc:
            return _member_error(exc)

    @router.post("/api/members")
    def invite_member(req: MemberIn, request: Request) -> JSONResponse:
        actor, denied = guards.admin_gate(request, write=True)
        if denied:
            return denied
        try:
            return JSONResponse({"member": ctx.members.add(req.email, req.role, actor)}, status_code=201)
        except MemberError as exc:
            return _member_error(exc)

    @router.patch("/api/members/{email}")
    def change_member_role(email: str, req: RoleIn, request: Request) -> JSONResponse:
        actor, denied = guards.admin_gate(request, write=True)
        if denied:
            return denied
        try:
            return JSONResponse({"member": ctx.members.set_role(email, req.role, actor)})
        except MemberError as exc:
            return _member_error(exc)

    @router.delete("/api/members/{email}")
    def remove_member(email: str, request: Request) -> JSONResponse:
        actor, denied = guards.admin_gate(request, write=True)
        if denied:
            return denied
        try:
            ctx.members.remove(email, actor)
            return JSONResponse({"ok": True})
        except MemberError as exc:
            return _member_error(exc)

