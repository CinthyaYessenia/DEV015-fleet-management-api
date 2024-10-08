from flask import Blueprint
from app.controllers.auth_controller import handle_login


bp_auth = Blueprint("auth", __name__)


@bp_auth.route("/auth/login", methods=["POST"])
def login():
    return handle_login()