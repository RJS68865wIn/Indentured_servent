#!/usr/bin/env python3
"""
Indentured Servant - Main Application Entry Point
Cybersecurity Assistant for Windows with AI Integration
"""
import os
import sys
import tkinter as tk
from pathlib import Path

# Add src directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from gui.main_window import MainWindow
from utils.logger import setup_logger
from utils.windows_tools import is_admin, run_as_admin

def main():
    """Main application entry point"""
    
    # Setup logging
    logger = setup_logger()
    logger.info("Starting Indentured Servant")
    
    # Check if running as admin (optional but recommended for some features)
    if not is_admin():
        logger.warning("Not running as administrator - some features may be limited")
        response = input("Run as administrator? (y/n): ")
        if response.lower() == 'y':
            run_as_admin()
            return
    
    # Create data directories if they don't exist
    data_dirs = [
        "data/logs",
        "data/vpn_configs", 
        "data/reports",
        "config"
    ]
    
    for dir_path in data_dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    # Start the GUI
    try:
        root = tk.Tk()
        app = MainWindow(root)
        logger.info("GUI initialized successfully")
        
        # Center window on screen
        window_width = 1200
        window_height = 800
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Set window icon (you'll need to create an icon file)
        try:
            icon_path = Path("assets/icon.ico")
            if icon_path.exists():
                root.iconbitmap(str(icon_path))
        except:
            pass
        
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"Error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()