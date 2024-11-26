from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.contrib.auth.models import AbstractUser,Group, Permission
from django.conf import settings
from datetime import date
from django.utils.timezone import now



class Query(models.Model):
    adult = models.PositiveIntegerField(default=0)
    child = models.PositiveIntegerField(default=0)
    infant = models.PositiveIntegerField(default=0)
    company = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255)
    city = models.CharField(max_length=255, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    mobile = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    status = models.CharField(max_length=50, choices=[
        ('Replied', 'Replied'),
        ('Open', 'Open'),
        ('Confirmed', 'Confirmed'),
        ('Lost', 'Lost'),
        ('NA(Reason for NA)', 'NA(Reason for NA)')
    ])
    duration = models.PositiveIntegerField(default=0)
    queryDate = models.DateField()
    tourStartDate = models.DateField()
    tourEndDate = models.DateField()
    uid = models.CharField(max_length=255, blank=True, null=True)
    agentHandling = models.CharField(max_length=50, blank=True, null=True)
    lastUpdatedBy = models.CharField(max_length=100, blank=True)  # Stores the username
    lastUpdatedAt = models.DateTimeField(default=now, blank=True)  #
    
    
    def __str__(self):
        return f"{self.name} - {self.uid}"


class Itinerary(models.Model):
    group_name = models.CharField(max_length=255)
    file_code = models.CharField(max_length=100, unique=True)
    total_pax = models.IntegerField()
    client_name = models.CharField(max_length=255)
    tour_date = models.DateField()
    flight = models.CharField(max_length=255)
    itinerary = models.TextField()
    date_of_qtn = models.DateField()
    agent = models.CharField(max_length=255)
    validity = models.CharField(max_length=255)

class Day(models.Model):
    itinerary = models.ForeignKey(Itinerary, on_delete=models.CASCADE, related_name='days')
    day = models.CharField(max_length=50)
    date = models.DateField()
    city = models.CharField(max_length=100)
    time = models.TimeField()
    service = models.CharField(max_length=255)
    mode = models.CharField(max_length=255)
    meal = models.CharField(max_length=255)
    duration = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

class Hotel(models.Model):
    itinerary = models.ForeignKey(Itinerary, on_delete=models.CASCADE, related_name='hotels')
    city = models.CharField(max_length=100)
    dates = models.CharField(max_length=100)  
    nights = models.IntegerField()
    hotel = models.CharField(max_length=255)

class QuotationSlab(models.Model):
    itinerary = models.ForeignKey(Itinerary, on_delete=models.CASCADE, related_name='quotation_slabs')
    slab = models.CharField(max_length=100)
    max_pax = models.IntegerField()
    min_pax = models.IntegerField()
    no_of_foc = models.IntegerField()
    pp_cost = models.DecimalField(max_digits=10, decimal_places=2)


class User(AbstractUser):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('owner', 'Owner'),
        ('admin', 'Admin'),
    ]
  
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

   
    def __str__(self):
        return self.username

class UserMetrics(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    login_count = models.IntegerField(default=0)

    def __str__(self):
        return f'{self.user.username} - Metrics'
    





