from django.conf.urls import patterns, include, url
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import admin

admin.autodiscover()


def dumbview(request):
    return HttpResponse('dumbview')


urlpatterns = patterns('',
    url('^logout-then-login/$', 'authuser.views.logout_then_login', name='logout_then_login'),
    url('^login_required/$', login_required(dumbview)),

    url('^', include('authuser.urls')),
)
