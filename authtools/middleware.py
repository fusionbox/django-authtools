from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url

from authtools.exceptions import LoginRequired


class LoginRequiredHandlerMiddleware(object):
    """
    Middleware to handle LoginRequired Exceptions
    """

    def process_exception(self, request, exception):
        if isinstance(exception, LoginRequired):
            if exception.next is None:
                next_url = request.get_full_path()
            else:
                next_url = resolve_url(exception.next)
            return redirect_to_login(next_url)
