from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()


urlpatterns = patterns(
    '',
    (r'^admin/', include(admin.site.urls)),
    (r'^login/$', 'django.contrib.auth.views.login', {'template_name':'admin/login.html'}),
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),
)

urlpatterns += patterns(
    'django_oauth.server.views',
    # Example:
    # (r'^oa_server/', include('oa_server.foo.urls')),

    (r'^oauth/request_token/$', 'request_token'),
    (r'^oauth/authorize/$', 'authorize'),
    (r'^oauth/access_token/$', 'access_token'),
    (r'^oauth/resource/$', 'get_resource'),
    (r'^api/register/$', 'register'),
    (r'^api/applications/$', 'applications'),
    (r'^api/logout/$', 'logout'),
)
