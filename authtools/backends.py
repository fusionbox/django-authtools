from django.contrib.auth.backends import ModelBackend


class CaseInsensitiveEmailBackend(ModelBackend):
    """
    This authentication backend assumes that usernames are email addresses and simply lowercases
    a username before an attempt is made to authenticate said username using Django's ModelBackend.

    Example usage:
        # In settings.py
        AUTHENTICATION_BACKENDS = ('authtools.backends.CaseInsensitiveEmailBackend',)
    """
    def authenticate(self, username=None, password=None, **kwargs):
        if username is not None:
            username = username.lower()

        return super(CaseInsensitiveEmailBackend, self).authenticate(
            username=username,
            password=password,
            **kwargs
        )
