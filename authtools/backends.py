from django.contrib.auth.backends import ModelBackend


class CaseInsensitiveEmailBackend(ModelBackend):
    """
    This authentication backend assumes that usernames are email addresses and simply lowercases
    a username before an attempt is made to authenticate said username using Django's ModelBackend.

    Example usage:
        # In settings.py
        AUTHENTICATION_BACKENDS = ('authtools.backends.CaseInsensitiveEmailBackend',)

    NOTE:
        A word of caution. Use of this backend presupposes a way to ensure that users cannot create
        usernames that differ only in case (e.g., joe@test.org and JOE@test.org). Using this backend
        in such a system is a huge security risk.
    """
    def authenticate(self, username=None, password=None, **kwargs):
        if username is not None:
            username = username.lower()

        return super(CaseInsensitiveEmailBackend, self).authenticate(
            username=username,
            password=password,
            **kwargs
        )
