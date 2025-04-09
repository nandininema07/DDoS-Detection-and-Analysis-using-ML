from flask import Flask
from flask_cors import CORS
from app.models import db

def create_app():
    app = Flask(__name__)
    CORS(app)

    # SQLite DB config
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    from app.routes.api import api_bp
    app.register_blueprint(api_bp)

    return app
