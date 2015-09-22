import django
from django.conf.urls import patterns, include, url
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import admin
from django.core.urlresolvers import reverse_lazy

from authtools import views
from authtools.forms import FriendlyPasswordResetForm

admin.autodiscover()


def dumbview(request):
    return HttpResponse('dumbview')


urlpatterns = [
    url(r'^reset_and_login/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.PasswordResetConfirmAndLoginView.as_view()),
    url(r'^logout-then-login/$', views.LogoutView.as_view(url=reverse_lazy('login')), name='logout_then_login'),
    url(r'^friendly_password_reset/$',
        views.PasswordResetView.as_view(form_class=FriendlyPasswordResetForm),
        name='friendly_password_reset'),
    url(r'^login_required/$', login_required(dumbview), name='login_required'),
    # From django.contrib.auth.tests.url
    url(r'^password_reset/html_email_template/$', views.PasswordResetView.as_view(html_email_template_name='registration/html_password_reset_email.html')),
    url(r'^', include('authtools.urls')),
]
