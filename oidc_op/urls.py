from django.urls import path

from . import views

app_name = 'oidc_op'

urlpatterns = [
    # path('login/', views.LoginAuthView.as_view(), name='login'),

    path('.well-known/<str:service>', views.well_known, name="oidc_op_well_known"),
    path('registration', views.registration, name="oidc_op_registration"),
    path('authorization', views.authorization, name="oidc_op_authorization"),

    path('verify/oidc_user_login/', views.verify_user, name="oidc_op_verify_user"),
    path('token', views.token, name="oidc_op_token"),
    path('userinfo', views.userinfo, name="oidc_op_userinfo"),

    path('session', views.session_endpoint, name="oidc_op_session"),
    # logout
    path('verify_logout', views.verify_logout, name="oidc_op_verify_logout"),
    path('post_logout', views.post_logout, name="oidc_op_post_logout"),
    # path('session_logout', views.session_logout, name="oidc_op_session_logout"),
    # path('logout', views.logout, name="oidc_op_logout"),
    path('rp_logout', views.rp_logout, name="oidc_op_rp_logout"),

    # path('bc_logout/<str:op_hash>', views.backchannel_logout,
         # name="oidc_op_backchannel_logout"),
    # path('fc_logout/<str:op_hash>', views.frontchannel_logout,
         # name="oidc_op_frontchannel_logout"),




]
