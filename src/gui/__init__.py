"""GUI package for Indentured Servant"""

try:
    from . import main_window
    from . import dashboard
    from . import scanner_tab
    from . import network_tab
    from . import email_tab
    from . import cyber_helper_tab
    from . import ai_tab
except ImportError:
    # Fallback for PyInstaller
    import src.gui.main_window as main_window
    import src.gui.dashboard as dashboard
    import src.gui.scanner_tab as scanner_tab
    import src.gui.network_tab as network_tab
    import src.gui.email_tab as email_tab
    import src.gui.cyber_helper_tab as cyber_helper_tab
    import src.gui.ai_tab as ai_tab

__all__ = ['main_window', 'dashboard', 'scanner_tab', 'network_tab', 'email_tab', 'cyber_helper_tab', 'ai_tab']