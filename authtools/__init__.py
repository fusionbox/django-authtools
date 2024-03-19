try:
    from importlib.metadata import version

    __version__ = version('django-authtools')
except ImportError:
    import pkg_resources

    __version__ = pkg_resources.get_distribution('django-authtools').version
