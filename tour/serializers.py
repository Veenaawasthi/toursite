from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Query
from .models import Itinerary, Day, Hotel, QuotationSlab 
from datetime import date
from .models import UserMetrics
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.utils.timezone import now


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'role']  
        extra_kwargs = {
            'password': {'write_only': True},  
            'role': {'required': False},  
        }

    def create(self, validated_data):
        role = validated_data.pop('role', 'user') 
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        user.role = role  
        user.save() 
        return user 
    
class UserMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserMetrics
        fields = ['user', 'login_count'] 

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        return token
        
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if user is None:
            raise serializers.ValidationError('Invalid username or password')
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled')

        return {'user': user}


class QuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = Query
        fields = '__all__'
        read_only_fields = ('lastUpdatedBy', 'lastUpdatedAt')

    def update(self, instance, validated_data):
        request_user = self.context['request'].user
        if request_user.is_authenticated:
            instance.lastUpdatedBy = request_user.username
        instance.lastUpdatedAt = now()

    
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance


class DaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Day
        fields = ['id', 'day', 'date', 'city', 'time', 'service', 'mode', 'meal', 'duration', 'price']

class HotelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hotel
        fields = ['id', 'city', 'dates', 'nights', 'hotel']

class QuotationSlabSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuotationSlab
        fields = ['id', 'slab', 'max_pax', 'min_pax', 'no_of_foc', 'pp_cost']

class ItinerarySerializer(serializers.ModelSerializer):
    days = DaySerializer(many=True)
    hotels = HotelSerializer(many=True)
    quotation_slabs = QuotationSlabSerializer(many=True)

    class Meta:
        model = Itinerary
        fields = [
            'id', 'group_name', 'file_code', 'total_pax', 'client_name', 
            'tour_date', 'flight', 'itinerary', 'date_of_qtn', 
            'agent', 'validity', 'days', 'hotels', 'quotation_slabs',
        ]

    def validate(self, data):
        total_pax = data.get('total_pax', 0)
        if total_pax < 1:
            raise serializers.ValidationError("Total pax must be a positive integer.")
        if 'tour_date' in data and data['tour_date'] < date.today():
            raise serializers.ValidationError("Tour date cannot be in the past.")
        return data

    def create(self, validated_data):
        days_data = validated_data.pop('days', [])
        hotels_data = validated_data.pop('hotels', [])
        quotation_slabs_data = validated_data.pop('quotation_slabs', [])
        
        itinerary = Itinerary.objects.create(**validated_data)
        self._create_or_update_related_objects(Day, days_data, itinerary)
        self._create_or_update_related_objects(Hotel, hotels_data, itinerary)
        self._create_or_update_related_objects(QuotationSlab, quotation_slabs_data, itinerary)

        return itinerary

    def update(self, instance, validated_data):
        days_data = validated_data.pop('days', None)
        hotels_data = validated_data.pop('hotels', None)
        quotation_slabs_data = validated_data.pop('quotation_slabs', None)

      
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

      
        if days_data is not None:
            self._create_or_update_related_objects(Day, days_data, instance)
        
        if hotels_data is not None:
            self._create_or_update_related_objects(Hotel, hotels_data, instance)

        if quotation_slabs_data is not None:
            self._create_or_update_related_objects(QuotationSlab, quotation_slabs_data, instance)

        return instance

    def _create_or_update_related_objects(self, model, data_list, itinerary):
        existing_objects = {obj.id: obj for obj in model.objects.filter(itinerary=itinerary)}

        for data in data_list:
            obj_id = data.get('id')
            if obj_id and obj_id in existing_objects:
                obj = existing_objects[obj_id]
                for attr, value in data.items():
                    if attr != 'id':  
                        setattr(obj, attr, value)
                obj.save()
            else:
                model.objects.create(itinerary=itinerary, **data)

        
        for obj_id in existing_objects.keys():
            if obj_id not in [data.get('id') for data in data_list]:
                existing_objects[obj_id].delete()



