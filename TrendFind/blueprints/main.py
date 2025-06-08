from flask import Blueprint, render_template
from flask_login import login_required, current_user

bp = Blueprint("main", __name__, url_prefix="/")

@bp.route("/")
def index():
    return render_template("base.html")      # replace with landing page

@bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)
