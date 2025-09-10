#!/usr/bin/env python3
"""
Database setup script for Secure Docker Manager
Initializes the database and creates a default admin user with optional 2FA.
"""
import sys
import os
from flask import Flask
from config import Config
from models import db, User
from datetime import datetime

# Create a minimal Flask app context for SQLAlchemy
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def setup_db():
    with app.app_context():
        print("🚀 Initializing database...")
        try:
            # Create all tables directly (simpler approach)
            print("Creating database tables...")
            db.create_all()
            print("✅ Database tables created successfully.")

            # Create default admin user if not exists
            default_username = "admin"
            default_password = "admin123"  # This should be changed immediately after first login

            admin_user = User.query.filter_by(username=default_username).first()
            if not admin_user:
                print(f"Creating default admin user: {default_username}")
                admin_user = User(
                    username=default_username, 
                    email="admin@example.com", 
                    is_admin=True, 
                    is_active=True,
                    totp_enabled=False  # 2FA disabled by default
                )
                admin_user.set_password(default_password)
                # Don't generate TOTP secret until user enables 2FA
                
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Default admin user created.")
                print(f"   Username: {default_username}")
                print(f"   Password: {default_password}")
                print("   ⚠️ Please change the default password immediately after first login.")
                print("   🔧 2FA is DISABLED by default - users can enable it in their profile.")
            else:
                print(f"Default admin user '{default_username}' already exists.")
                # Ensure 2FA is disabled by default for existing users
                if admin_user.totp_enabled is None:
                    admin_user.totp_enabled = False
                    db.session.commit()
                    print(f"✅ 2FA status set to disabled for existing admin user '{default_username}'.")
                    print("   🔧 Users can enable 2FA in their profile settings.")

            print("\n✅ Database setup completed successfully!")
            print("\n🔧 2FA Configuration:")
            print("   • 2FA is OPTIONAL and disabled by default")
            print("   • Users can enable 2FA in their profile settings")
            print("   • Admin can manage user 2FA settings")
            print("   • QR codes are generated only when enabling 2FA")
            return True
        except Exception as e:
            print(f"\n❌ An error occurred during database setup: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    if not setup_db():
        print("\n❌ Database setup failed!")
        sys.exit(1)
