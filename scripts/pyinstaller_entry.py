"""PyInstaller entry script: provides a single entrypoint used for building an executable.

This script imports and runs `src.main.main()` so packaging is consistent with the module entry point.
"""
import sys
import os
import traceback

if __name__ == '__main__':
    try:
        # Add bundled directory to Python path for PyInstaller
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            bundle_dir = sys._MEIPASS
        else:
            # Running as script
            bundle_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Add bundle directory to path so absolute imports work
        if bundle_dir not in sys.path:
            sys.path.insert(0, bundle_dir)
        
        # Import here so PyInstaller collects dependencies
        import src.main as app
        app.main()
    except Exception as e:
        # Show error in GUI messagebox before exiting
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Application Error",
                f"Failed to start Indentured Servant:\n\n{str(e)}\n\nCheck logs for details."
            )
        except:
            # Fallback if tkinter fails
            print(f"FATAL ERROR: {e}")
            traceback.print_exc()
        sys.exit(1)
