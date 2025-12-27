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
    
    # Enforce admin privileges: relaunch with elevation if not already admin
    # This is required for several scan actions (Defender, services, registry)
    if not is_admin():
        logger.warning("Elevating to administrator for full scanning capabilities")
        try:
            run_as_admin()
            return
        except Exception as e:
            logger.error(f"Elevation failed: {e}")
            # Continue without exit so user sees the warning in GUI
    
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
        # Show error in messagebox instead of console for windowed apps
        try:
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Application Error", f"Failed to start:\n\n{e}")
        except:
            print(f"Error: {e}")
            # Only try input if we have a console
            if not getattr(sys, 'frozen', False):
                try:
                    input("Press Enter to exit...")
                except (EOFError, OSError):
                    pass

if __name__ == "__main__":
    main()