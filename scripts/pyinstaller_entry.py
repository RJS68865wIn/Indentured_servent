"""PyInstaller entry script: provides a single entrypoint used for building an executable.

This script imports and runs `src.main.main()` so packaging is consistent with the module entry point.
"""
import sys
import traceback

if __name__ == '__main__':
    try:
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
