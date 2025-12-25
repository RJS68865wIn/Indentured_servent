"""Utils package for Indentured Servant"""

try:
    from . import logger
    from . import windows_tools
    from . import helpers
except ImportError:
    # Fallback for PyInstaller
    import src.utils.logger as logger
    import src.utils.windows_tools as windows_tools
    import src.utils.helpers as helpers

__all__ = ['logger', 'windows_tools', 'helpers']