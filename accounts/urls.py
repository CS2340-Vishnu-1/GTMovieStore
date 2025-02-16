from django.urls import path
from . import views
urlpatterns = [
    path('signup', views.signup, name='accounts.signup'),
    path('login/', views.login, name='accounts.login'),
    path('logout/', views.logout, name='accounts.logout'),
    path('orders/', views.orders, name='accounts.orders'),
    path('password_reset/', views.password_reset_request, name='accounts.password_reset'),
    path('password_reset/done/', views.password_reset_done, name='accounts.password_reset_done'),
    path('password_reset/sent/', views.password_reset_sent, name='accounts.password_reset_sent'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='accounts.password_reset_confirm'),
]