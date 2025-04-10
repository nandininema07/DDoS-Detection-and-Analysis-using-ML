from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate  # Import Flask-Migrate
from app.models import db

def create_app():
    app = Flask(__name__)
    CORS(app)

    # SQLite DB config
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # Initialize Flask-Migrate
    migrate = Migrate(app, db)

    with app.app_context():
        db.create_all()  # This will create the database tables, but you will use migrations for future changes

    from app.routes.api import api_bp
    app.register_blueprint(api_bp)

    return app
