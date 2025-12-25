"""PyInstaller entry script: provides a single entrypoint used for building an executable.

This script imports and runs `src.main.main()` so packaging is consistent with the module entry point.
"""

if __name__ == '__main__':
    # Import here so PyInstaller collects dependencies
    import src.main as app
    app.main()
