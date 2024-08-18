from django.urls import path
from .views import *
from .views import delete_todo
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("", register_page, name="register_page"),
    path("index", index, name="index"),
    # path("login", login_page, name="login_page"),
    path("login/", LoginView.as_view(), name="login_page"),
    path("logout", logout_view, name="logout"),
    path("ced_todo", ced_todo, name="ced_todo"),
    path("my_blog", my_blog, name="my_blog"),
    path("delete_todo/<int:id>/", delete_todo, name="delete_todo"),
    path("edit_todo/<int:id>/", edit_todo, name="edit_todo"),
    path("verify_otp", verify_otp, name="verify_otp"),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('view_todo/<int:id>/', view_todo, name='view_todo'),
    path("user_profile", user_profile, name="user_profile"),
    path("edit_profile", edit_profile, name="edit_profile"),
    path("premium", premium, name="premium"),
    path('forgot_password/', forgotpasswordpage, name='forgot_password'),
    path('change_password/<str:token>/', changepassword, name='change_password'),
    path('todo/<int:id>/like/', like_todo, name='like_todo'),
    path('todo/<int:id>/comment/', add_comment, name='add_comment'),
    path('comment/<int:comment_id>/delete/', delete_comment, name='delete_comment'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)