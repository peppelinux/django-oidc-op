from django.urls import path

from . import views

app_name = 'oidc_provider'


urlpatterns = [
    path('.well-known/<str:service>', views.well_known,
         name="_well_known"),
    path('registration', views.registration,
         name="registration"),
    path('registration_read', views.registration_read,
         name="registration_read"),

    path('authorization', views.authorization,
         name="authorization"),

    path('verify/oidc_user_login/', views.verify_user,
         name="verify_user"),
    path('token', views.token, name="token"),
    path('userinfo', views.userinfo, name="userinfo"),
    path('introspection', views.introspection, name="introspection"),

    path('check_session_iframe', views.check_session_iframe,
         name="check_session_iframe"),
    path('session', views.session_endpoint, name="session"),
    # logout
    path('verify_logout', views.verify_logout,
         name="verify_logout"),
    path('post_logout', views.post_logout, name="post_logout"),
    path('rp_logout', views.rp_logout, name="rp_logout"),
]
