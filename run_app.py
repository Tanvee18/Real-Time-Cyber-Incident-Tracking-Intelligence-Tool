#!/usr/bin/env python3
"""
Startup script for the Cyber Incident Tracking Dashboard
"""

import subprocess
import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        'flask',
        'mysql-connector-python',
        'requests',
        'feedparser'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 Install them with:")
        print(f"   pip install {' '.join(missing_packages)}")
        return False
    
    print("✅ All required packages are installed")
    return True

def check_database():
    """Check database connection"""
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Tanvee@18",
            database="project"
        )
        conn.close()
        print("✅ Database connection successful")
        return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("\n🔧 Make sure MySQL is running and the database exists")
        print("   Run: mysql -u root -p < database_schema.sql")
        return False

def run_cyber_feeds():
    """Run the cyber feeds processing"""
    try:
        print("🔄 Processing cyber feeds...")
        from cyber_feeds_oop import main
        main()
        print("✅ Cyber feeds processed successfully")
        return True
    except Exception as e:
        print(f"❌ Error processing cyber feeds: {e}")
        return False

def start_web_app():
    """Start the Flask web application"""
    try:
        print("🚀 Starting web application...")
        print("📱 Dashboard will be available at: http://localhost:5000")
        print("🛑 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"❌ Error starting web application: {e}")
        return False

def main():
    """Main startup function"""
    print("🛡️  Cyber Incident Tracking Dashboard")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("app.py").exists():
        print("❌ app.py not found. Make sure you're in the correct directory.")
        return
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Check database
    if not check_database():
        return
    
    # Ask user what to do
    print("\nWhat would you like to do?")
    print("1. Process cyber feeds only")
    print("2. Start web dashboard only")
    print("3. Process feeds and start dashboard")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == "1":
        run_cyber_feeds()
    elif choice == "2":
        start_web_app()
    elif choice == "3":
        if run_cyber_feeds():
            print("\n" + "=" * 50)
            start_web_app()
    elif choice == "4":
        print("👋 Goodbye!")
    else:
        print("❌ Invalid choice. Please run the script again.")

if __name__ == "__main__":
    main()


