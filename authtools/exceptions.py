class LoginRequired(Exception):
    """
    This can be used to redirect to the login page within a view.
    This has to be used with the middleware:
    ``authtools.middleware.LoginRequiredHandlerMiddleware``
    """

    def __init__(self, next=None):
        self.next = next
