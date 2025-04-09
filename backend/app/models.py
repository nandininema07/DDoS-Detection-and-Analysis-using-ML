from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(120), unique=True, nullable=False) 


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    datetime = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # Safe, Flagged, DDoS
    confidence = db.Column(db.Float)
    details = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    website_url = db.Column(db.String(200))
    alert_email = db.Column(db.String(120))
    alert_phone = db.Column(db.String(15))
    email_alerts = db.Column(db.Boolean, default=True)
    call_alerts = db.Column(db.Boolean, default=False)
