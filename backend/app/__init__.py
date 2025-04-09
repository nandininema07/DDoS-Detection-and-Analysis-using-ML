from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import os

db = SQLAlchemy()

def create_app():
    load_dotenv()
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")

    db.init_app(app)

    from .routes.auth import auth_bp
    from .routes.detect import detect_bp
    from .routes.dashboard import dashboard_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(detect_bp, url_prefix='/api')
    app.register_blueprint(dashboard_bp, url_prefix='/api')

    return app
