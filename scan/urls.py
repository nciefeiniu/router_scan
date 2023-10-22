from django.urls import path

from scan.views import LoginView, UserInfoView, LogoutView, ScanView


urlpatterns = [
    path('user/login/', LoginView.as_view(), name='login'),
    path('user/info/', UserInfoView.as_view(), name='userinfo'),
    path('user/logout/', LogoutView.as_view(), name='userinfo'),
    path('scan/', ScanView.as_view(), name='scan_host'),

]