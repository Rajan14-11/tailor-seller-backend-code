from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    MyAdminProductViewSet,
    MyAdminSellerInfoViewSet,
    CategoryViewSet,
    BusinessInfoViewSet,
    StoreInfoViewSet,
    ProductInfoViewSet,
    TaxInfoViewSet,
    VerifyDetailsViewSet,
    SellerInfoViewSet,
    SellerProductViewSet,
    SellerViewSet,
    OrderViewSet,
    SellerReviewViewSet,
    SignupAPIView,
    LoginAPIView,
    LogoutAPIView
)

router = DefaultRouter()
router.register(r'my-admin-products', MyAdminProductViewSet)
router.register(r'my-admin-seller-info', MyAdminSellerInfoViewSet)
router.register(r'categories', CategoryViewSet)
router.register(r'business-info', BusinessInfoViewSet)
router.register(r'store-info', StoreInfoViewSet)
router.register(r'product-info', ProductInfoViewSet)
router.register(r'tax-info', TaxInfoViewSet)
router.register(r'verify-details', VerifyDetailsViewSet)
router.register(r'seller-info', SellerInfoViewSet)
router.register(r'seller-products', SellerProductViewSet)
router.register(r'sellers', SellerViewSet)
router.register(r'orders', OrderViewSet)
router.register(r'seller-reviews', SellerReviewViewSet)

urlpatterns = [
    path('startseller/', include(router.urls)),
    path('startseller/signup/', SignupAPIView.as_view(), name='api_signup'),
    path('startseller/login/', LoginAPIView.as_view(), name='api_login'),
    path('startseller/logout/', LogoutAPIView.as_view(), name='api_logout'),  # Add this line for LogoutAPIView
    # Add any additional URLs if needed
]
