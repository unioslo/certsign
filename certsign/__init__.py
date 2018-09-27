try:
    import __builtin__

    if not hasattr(__builtin__, 'FileExistsError'):
        class FileExistsError(OSError):
            """ File already exists. """
        __builtin__.FileExistsError = FileExistsError
except ImportError:
    pass
