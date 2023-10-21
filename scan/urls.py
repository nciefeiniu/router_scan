from django.urls import path

from scan.views import LoginView, UserInfoView, LogoutView


urlpatterns = [
    path('user/login/', LoginView.as_view(), name='login'),
    path('user/info/', UserInfoView.as_view(), name='userinfo'),
    path('user/logout/', LogoutView.as_view(), name='userinfo'),

]