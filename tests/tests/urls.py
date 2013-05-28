from django.conf.urls import patterns, include, url
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import admin

admin.autodiscover()


def dumbview(request):
    return HttpResponse('dumbview')


urlpatterns = patterns('',
    url('^logout-then-login/$', 'authtools.views.logout_then_login', name='logout_then_login'),
    url('^login_required/$', login_required(dumbview)),
    url('^reset_and_login/(?P<uidb36>[0-9A-Za-z]{1,13})-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 'authtools.views.password_reset_confirm_and_login'),

    url('^', include('authtools.urls')),
)
