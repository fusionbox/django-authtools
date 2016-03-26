from django.contrib.auth.backends import ModelBackend


class CaseInsensitiveUsernameFieldBackendMixin(object):
    def authenticate(self, username=None, password=None, **kwargs):
        """
        This authentication backend assumes that usernames are email addresses and simply
        lowercases a username before an attempt is made to authenticate said username using a
        superclass's authenticate method. This superclass should be either a user-defined
        authentication backend, or a Django-provided authentication backend (e.g., ModelBackend).

        Example usage:
            See CaseInsensitiveUsernameFieldBackend, below.

        NOTE:
            A word of caution. Use of this backend presupposes a way to ensure that users cannot
            create usernames that differ only in case (e.g., joe@test.org and JOE@test.org). It is
            advised that you use this backend in conjunction with the
            CaseInsensitiveUsernameFieldCreationForm provided in the forms module.
        """
        if username is not None:
            username = username.lower()

        return super(CaseInsensitiveUsernameFieldBackendMixin, self).authenticate(
            username=username,
            password=password,
            **kwargs
        )


class CaseInsensitiveUsernameFieldModelBackend(CaseInsensitiveUsernameFieldBackendMixin, ModelBackend):
    pass


# alias for the old name for backwards-compatability
CaseInsensitiveEmailBackendMixin = CaseInsensitiveUsernameFieldBackendMixin
CaseInsensitiveEmailModelBackend = CaseInsensitiveUsernameFieldModelBackend
