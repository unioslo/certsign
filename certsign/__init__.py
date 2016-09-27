try:
    import builtins
except ImportError:
    import __builtin__ as builtins

if not hasattr(builtins, 'FileExistsError'):
    class FileExistsError(OSError):
        """ File already exists. """
    builtins.FileExistsError = FileExistsError
