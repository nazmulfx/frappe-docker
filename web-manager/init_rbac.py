#!/usr/bin/env python3
"""
Database initialization and RBAC setup script
Run this after updating models to initialize roles and permissions
"""

from app import app
from models import db, init_rbac_system

def main():
    print("🔧 Initializing RBAC System...")
    print("=" * 50)
    
    with app.app_context():
        # Create all database tables
        print("📊 Creating database tables...")
        db.create_all()
        print("✅ Database tables created")
        
        # Initialize RBAC system
        print("\n🔐 Setting up roles and permissions...")
        success = init_rbac_system()
        
        if success:
            print("\n" + "=" * 50)
            print("✅ RBAC SYSTEM INITIALIZED SUCCESSFULLY!")
            print("=" * 50)
            print("\n📋 Default Roles Created:")
            print("  • Administrator - Full system access")
            print("  • Manager - Manage containers, apps, view users")
            print("  • Developer - Manage containers and applications")
            print("  • Operator - Start/stop containers, view logs")
            print("  • Viewer - Read-only access")
            print("\n🔑 You can now assign roles to users via the User Management interface")
            print("")
        else:
            print("\n❌ RBAC initialization failed. Check errors above.")
            return 1
    
    return 0

if __name__ == '__main__':
    exit(main())


