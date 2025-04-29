from app import app, db, User
from werkzeug.security import generate_password_hash
import os

with app.app_context():
    db.create_all()
    if not User.query.first():
        admin_password = os.getenv('ADMIN_PASSWORD', 'default_admin_password')  # Fallback password
        User(
            username='admin',
            email='admin@example.com',
            password=generate_password_hash(admin_password),
            is_admin=True
        ).save()
        print(f"Admin created with password: {admin_password}")