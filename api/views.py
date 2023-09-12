from rest_framework import generics, viewsets
from rest_framework.response import responses
from django.contrib.auth import login, authenticate,get_user_model,logout
from django.contrib.auth.forms import AuthenticationForm
from rest_framework import status,permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer, LoginSerializer
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from .models import (
    MyAdminProduct,
    MyAdminSellerInfo,
    Category,
    BusinessInfo,
    StoreInfo,
    ProductInfo,
    TaxInfo,
    VerifyDetails,
    SellerInfo,
    SellerProduct,
    Seller,
    Order,
    SellerReview,
)
from .serializers import (
    MyAdminProductSerializer,
    MyAdminSellerInfoSerializer,
    CategorySerializer,
    BusinessInfoSerializer,
    StoreInfoSerializer,
    ProductInfoSerializer,
    TaxInfoSerializer,
    VerifyDetailsSerializer,
    SellerInfoSerializer,
    SellerProductSerializer,
    SellerSerializer,
    OrderSerializer,
    SellerReviewSerializer,
)
User = get_user_model()

class SignupAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = request.data.get('confirm_password')  # Add 'confirm_password' field to your form
            if password == confirm_password:
                user = serializer.save()
                login(request, user)
                return Response({'message': 'You have been registered and logged in successfully.'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return Response({'message': 'You have been logged in successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@permission_classes([IsAuthenticated])  
class LogoutAPIView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'You have been logged out successfully.'}, status=status.HTTP_200_OK)


class MyAdminProductViewSet(viewsets.ModelViewSet):
    queryset = MyAdminProduct.objects.all()
    serializer_class = MyAdminProductSerializer

class MyAdminSellerInfoViewSet(viewsets.ModelViewSet):
    queryset = MyAdminSellerInfo.objects.all()
    serializer_class = MyAdminSellerInfoSerializer

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

class BusinessInfoViewSet(viewsets.ModelViewSet):
    queryset = BusinessInfo.objects.all()
    serializer_class = BusinessInfoSerializer

class StoreInfoViewSet(viewsets.ModelViewSet):
    queryset = StoreInfo.objects.all()
    serializer_class = StoreInfoSerializer

class ProductInfoViewSet(viewsets.ModelViewSet):
    queryset = ProductInfo.objects.all()
    serializer_class = ProductInfoSerializer

class TaxInfoViewSet(viewsets.ModelViewSet):
    queryset = TaxInfo.objects.all()
    serializer_class = TaxInfoSerializer

class VerifyDetailsViewSet(viewsets.ModelViewSet):
    queryset = VerifyDetails.objects.all()
    serializer_class = VerifyDetailsSerializer

class SellerInfoViewSet(viewsets.ModelViewSet):
    queryset = SellerInfo.objects.all()
    serializer_class = SellerInfoSerializer

class SellerProductViewSet(viewsets.ModelViewSet):
    queryset = SellerProduct.objects.all()
    serializer_class = SellerProductSerializer

class SellerViewSet(viewsets.ModelViewSet):
    queryset = Seller.objects.all()
    serializer_class = SellerSerializer

class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer

class SellerReviewViewSet(viewsets.ModelViewSet):
    queryset = SellerReview.objects.all()
    serializer_class = SellerReviewSerializer
