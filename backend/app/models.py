from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100))  # Store hashed password
    api_key = db.Column(db.String(36), unique=True, nullable=False)
    settings = db.relationship('Setting', backref='user', lazy=True)  # Relationship with Settings
    logs = db.relationship('Log', backref='user', lazy=True)  # Relationship with Logs

    def __repr__(self):
        return f'<User {self.username}>'

# Log Model
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), index=True)  # Indexed for fast querying
    datetime = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # Safe, Flagged, DDoS
    confidence = db.Column(db.Float)  # Confidence score of attack detection
    details = db.Column(db.Text)  # Additional details about the attack
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Reference to the User who owns this log

    def __repr__(self):
        return f'<Log {self.ip} - {self.status}>'

# Setting Model
class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website_url = db.Column(db.String(200))
    alert_email = db.Column(db.String(120))
    alert_phone = db.Column(db.String(15))
    email_alerts = db.Column(db.Boolean, default=True)
    call_alerts = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('settings', lazy=True))

    def __repr__(self):
        return f'<Setting {self.website_url} - {self.user.username}>'
