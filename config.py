# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN') or 'your-admin-token-here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join('instance', 'cybersphere.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_VERIFY_TIMEOUT = 1800  # 30 minutes