import django
from django.conf.urls import patterns, include, url
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import admin

from authtools.views import PasswordResetView
from authtools.forms import FriendlyPasswordResetForm

admin.autodiscover()


def dumbview(request):
    return HttpResponse('dumbview')


if django.VERSION < (1, 6):
    urlpatterns = patterns('authtools.views',
        url('^reset_and_login/(?P<uidb36>[0-9A-Za-z]{1,13})-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 'password_reset_confirm_and_login'),
    )
else:
    urlpatterns = patterns('authtools.views',
        url(r'^reset_and_login/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 'password_reset_confirm_and_login'),
    )

urlpatterns += patterns('',
    url('^logout-then-login/$', 'authtools.views.logout_then_login', name='logout_then_login'),
    url('^friendly_password_reset/$',
        PasswordResetView.as_view(form_class=FriendlyPasswordResetForm),
        name='friendly_password_reset'),
    url('^login_required/$', login_required(dumbview), name='login_required'),
    # From django.contrib.auth.tests.url
    url('^password_reset/html_email_template/$', 'django.contrib.auth.views.password_reset', dict(html_email_template_name='registration/html_password_reset_email.html')),
    url('^', include('authtools.urls')),
)
