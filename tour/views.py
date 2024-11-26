from django.contrib.auth.models import User
from rest_framework import generics
from .serializers import UserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import status
from rest_framework import serializers
from .models import Query
from .serializers import QuerySerializer
from .serializers import LoginSerializer
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions
from .serializers import ItinerarySerializer
from rest_framework import viewsets
from .models import Itinerary, Day, Hotel, QuotationSlab
from .serializers import ItinerarySerializer, DaySerializer, HotelSerializer, QuotationSlabSerializer
from .models import UserMetrics
from .serializers import UserMetricsSerializer
from django.contrib.auth import get_user_model
import jwt
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from django.utils.timezone import now
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt




import logging

logger = logging.getLogger(__name__)

User = get_user_model()

# Create user view
class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        if user:
            UserMetrics.objects.create(user=user)
        else:
            raise serializers.ValidationError('User could not be created.')

# UserMetrics ViewSet
class UserMetricsViewSet(viewsets.ModelViewSet):
    serializer_class = UserMetricsSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        user = self.request.user
        queryset = UserMetrics.objects.none()

        if user.is_authenticated:
            if hasattr(user, 'role'):
                if user.role == 'admin':
                    queryset = UserMetrics.objects.all()
                elif user.role == 'owner':
                    queryset = UserMetrics.objects.filter(user=user)
                
                username = self.request.query_params.get('username')
                if username:
                    user_to_filter = User.objects.filter(username=username).first()
                    if user_to_filter:
                        queryset = queryset.filter(user=user_to_filter)

        return queryset

    def retrieve(self, request, *args, **kwargs):
        user = request.user
        if user.role not in ['admin', 'owner']:
            return Response({'detail': 'You do not have permission to view this detail.'}, status=status.HTTP_403_FORBIDDEN)
        
        return super().retrieve(request, *args, **kwargs)


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [] 

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            # Update user metrics
            user_metrics, created = UserMetrics.objects.get_or_create(user=user)
            user_metrics.login_count += 1
            user_metrics.save()

            role = getattr(user, 'role', 'user')
            return Response({
                'refresh': str(refresh),
                'access': str(access_token),
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    'metrics': {
                        'login_count': user_metrics.login_count,
                    }
                }
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        return Response({
            'message': 'Login endpoint. Use POST to log in.',
            'documentation': {
                'url': request.build_absolute_uri('/login/'),
                'method': 'POST',
                'fields': {
                    'username': 'Your username',
                    'password': 'Your password',
                }
            }
        }, status=status.HTTP_200_OK)

class DecodeTokenView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Get the Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        if not auth_header:
            return Response({'error': 'Authorization header not found.'}, status=401)

        try:
            token = auth_header.split(' ')[1]  
        except IndexError:
            return Response({'error': 'Invalid authorization header format.'}, status=400)

        try:
            decoded_data = UntypedToken(token).payload  
            return Response(decoded_data) 
        except TokenError as e:
            return Response({'error': str(e)}, status=401)

# Query view for handling queries
logger = logging.getLogger(__name__)

class QueryView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @method_decorator(csrf_exempt)
    def get(self, request, *args, **kwargs):
        """
        Retrieve a list of queries or a specific query by UID.
        """
        uid = kwargs.get('uid', None)
        if uid:
            query = get_object_or_404(Query, uid=uid)
            serializer = QuerySerializer(query)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            queries = Query.objects.all()
            serializer = QuerySerializer(queries, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
  
        logger.debug(f"User making the request: {request.user}")

        data = request.data.copy()
        
      
        username = request.user.username  # or request.auth.get('username') if you need to decode
        if username:
            data['lastUpdatedBy'] = username
        else:
            logger.warning("User is not authenticated or username is missing.")

        data['lastUpdatedAt'] = now()

        uid = data.get('uid')
        if uid:
            existing_query = Query.objects.filter(uid=uid).first()
            if existing_query:
                serializer = QuerySerializer(existing_query, data=data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer = QuerySerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt)
    def put(self, request, uid, *args, **kwargs):
     
        query = get_object_or_404(Query, uid=uid)
        data = request.data.copy()
        
     
        username = request.user.username 
        if username:
            data['lastUpdatedBy'] = username
        data['lastUpdatedAt'] = now()

        serializer = QuerySerializer(query, data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, uid, *args, **kwargs):
        """
     .
        """
        query = get_object_or_404(Query, uid=uid)
        query.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    


logger = logging.getLogger(__name__)

class ItineraryView(APIView):
    def get(self, request, *args, **kwargs):
        itinerary_file_code = kwargs.get('file_code')
        if itinerary_file_code:
            itinerary = get_object_or_404(Itinerary, file_code=itinerary_file_code)
            serializer = ItinerarySerializer(itinerary)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        itineraries = Itinerary.objects.all()
        serializer = ItinerarySerializer(itineraries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        file_code = data.get('file_code')

        if file_code:
            existing_itinerary = Itinerary.objects.filter(file_code=file_code).first()
            if existing_itinerary:
                serializer = ItinerarySerializer(existing_itinerary, data=data, context={'request': request})
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                logger.error(f"Update Itinerary Errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer = ItinerarySerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error(f"Create Itinerary Errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, file_code, *args, **kwargs):
        itinerary = get_object_or_404(Itinerary, file_code=file_code)
        data = request.data.copy()

        new_file_code = data.get('file_code', itinerary.file_code)
        if new_file_code != itinerary.file_code:
            return Response({'file_code': 'The file code cannot be changed.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ItinerarySerializer(itinerary, data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        logger.error(f"Update Itinerary Errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, file_code, *args, **kwargs):
        itinerary = get_object_or_404(Itinerary, file_code=file_code)
        itinerary.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

from googletrans import Translator

translator = Translator()

def translate_text(text, dest_language='ja'):
    try:
        translated = translator.translate(text, dest=dest_language)
        return translated.text
    except Exception as e:
        print(f"Error translating text: {e}")
        return text  

class ManageDaysView(APIView):
    def get(self, request, file_code, *args, **kwargs):
        
        days = Day.objects.filter(itinerary__file_code=file_code)
        
        for day in days:
            day.service = translate_text(day.service)
        
        serializer = DaySerializer(days, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, file_code, *args, **kwargs):
        data = request.data.copy()
        data['itinerary'] = file_code
        
       
        if 'service' in data:
            data['service'] = translate_text(data['service'])

        serializer = DaySerializer(data=data, context={'request': request})
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, file_code, day_id, *args, **kwargs):
      
        day = get_object_or_404(Day, id=day_id, itinerary__file_code=file_code)
        data = request.data.copy()

       
        new_file_code = data.get('file_code', file_code)
        if new_file_code != file_code:
            return Response({'file_code': 'The file code cannot be changed.'}, status=status.HTTP_400_BAD_REQUEST)

       
        if 'service' in data:
            data['service'] = translate_text(data['service'])

        serializer = DaySerializer(day, data=data, context={'request': request})
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, file_code, day_id, *args, **kwargs):
     
        day = get_object_or_404(Day, id=day_id, itinerary__file_code=file_code)
        day.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ManageHotelsView(APIView):
    def get(self, request, file_code, *args, **kwargs):
        hotels = Hotel.objects.filter(file_code=file_code)
        serializer = HotelSerializer(hotels, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, file_code, *args, **kwargs):
        data = request.data.copy()
        data['itinerary'] = file_code
        serializer = HotelSerializer(data=data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, file_code, hotel_id, *args, **kwargs):
        hotel = get_object_or_404(Hotel, id=hotel_id, file_code=file_code)
        data = request.data.copy()

        new_file_code = data.get('file_code', hotel.file_code)
        if new_file_code != file_code:
            return Response({'file_code': 'The file code cannot be changed.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = HotelSerializer(hotel, data=data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, file_code, hotel_id, *args, **kwargs):
        hotel = get_object_or_404(Hotel, id=hotel_id, file_code=file_code)
        hotel.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ManageQuotationSlabsView(APIView):
    def get(self, request, file_code, *args, **kwargs):
        quotation_slabs = QuotationSlab.objects.filter(file_code=file_code)
        serializer = QuotationSlabSerializer(quotation_slabs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, file_code, *args, **kwargs):
        data = request.data.copy()
        data['itinerary'] = file_code
        serializer = QuotationSlabSerializer(data=data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, file_code, slab_id, *args, **kwargs):
        slab = get_object_or_404(QuotationSlab, id=slab_id, file_code=file_code)
        data = request.data.copy()

        new_file_code = data.get('file_code', slab.file_code)
        if new_file_code != file_code:
            return Response({'file_code': 'The file code cannot be changed.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = QuotationSlabSerializer(slab, data=data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, file_code, slab_id, *args, **kwargs):
        slab = get_object_or_404(QuotationSlab, id=slab_id, file_code=file_code)
        slab.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


