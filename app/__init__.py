from flask import Flask
from .db import init_db, close_db
from .routes import bp


def create_app():
    app = Flask(
        __name__,
        instance_relative_config=False,
        template_folder="../templates",
        static_folder="../static"
    )
    app.config.from_object("config")
    app.config["MAX_CONTENT_LENGTH"] = app.config.get("MAX_CONTENT_LENGTH")

    app.teardown_appcontext(close_db)
    app.register_blueprint(bp)

    with app.app_context():
        init_db()

    return app
