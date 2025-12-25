#!/usr/bin/env python3
"""
Simple launcher script for Indentured Servant
Run this to start the application
"""
import os
import sys
import subprocess

def check_dependencies():
    """Check if required dependencies are installed"""
    required = ['cryptography', 'requests', 'psutil']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def main():
    """Launch the application"""
    print("🚀 Launching Indentured Servant...")
    print("=" * 50)
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"\n❌ Missing dependencies: {', '.join(missing)}")
        print("\nRun the installer:")
        print("  scripts\\install_dependencies.bat")
        print("\nOr install manually:")
        print("  pip install " + " ".join(missing))
        input("\nPress Enter to exit...")
        return
    
    # Import and run main application
    try:
        from src.main import main as app_main
        app_main()
    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        print("\nMake sure you're running from the correct directory.")
        print(f"Current directory: {os.getcwd()}")
        input("\nPress Enter to exit...")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()