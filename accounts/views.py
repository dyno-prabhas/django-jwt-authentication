from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate, login

from django.shortcuts import redirect, render

from rest_framework.renderers import TemplateHTMLRenderer



class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            # refresh = RefreshToken.for_user(user)
            # return Response({
            #     'refresh': str(refresh),
            #     'access': str(refresh.access_token),
            # }, status=status.HTTP_200_OK)

            login(request, user)
            return render(request, 'user_details.html')
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)



class UserDetailsView(APIView):
    permission_classes = [IsAuthenticated] 
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'user_details.html' 

    def get(self, request):
        user = request.user
        return Response({'user': user}, template_name=self.template_name)