from django.urls import path

from . import views

app_name = 'oidc_op'

urlpatterns = [
    # path('login/', views.LoginAuthView.as_view(), name='login'),

    path('.well-known/<str:service>', views.well_known, name="oidc_well_known"),
    path('registration', views.registration, name="oidc_registration"),
    path('authorization', views.authorization, name="oidc_authorization"),

]
