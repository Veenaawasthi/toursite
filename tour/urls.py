from django.urls import path
from .views import (
    QueryView,
    ItineraryView,
    ManageDaysView,
    ManageHotelsView,
    ManageQuotationSlabsView,
    CreateUserView,
    LoginView,
    UserMetricsViewSet,
    UserListView,
   
)
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from .views import DecodeTokenView

urlpatterns = [
    path('user/', CreateUserView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', TokenObtainPairView.as_view(), name='get_token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('query/', QueryView.as_view(), name='query-list'),  # For GET and POST requests
    path('query/<str:uid>/', QueryView.as_view(), name='query-detail'),  # For GET, PUT, and DELETE requests
    path('itineraries/', ItineraryView.as_view(), name='itinerary-list'),
    path('itineraries/<str:file_code>/', ItineraryView.as_view(), name='itinerary-detail'),
    path('itineraries/<str:file_code>/days/', ManageDaysView.as_view(), name='manage-days'),
    path('itineraries/<str:file_code>/days/<int:id>/', ManageDaysView.as_view(), name='manage-day-detail'),
    path('itineraries/<str:file_code>/hotels/', ManageHotelsView.as_view(), name='manage-hotels'),
    path('itineraries/<str:file_code>/hotels/<int:id>/', ManageHotelsView.as_view(), name='manage-hotel-detail'),
    path('itineraries/<str:file_code>/quotation-slabs/', ManageQuotationSlabsView.as_view(), name='manage-quotation-slabs'),
    path('itineraries/<str:file_code>/quotation-slabs/<int:id>/', ManageQuotationSlabsView.as_view(), name='manage-quotation-slab-detail'),
    path('user-metrics/', UserMetricsViewSet.as_view({'get': 'list'}), name='user-metrics-list'),
    path('user-metrics/<int:pk>/', UserMetricsViewSet.as_view({'get': 'retrieve'}), name='user-metrics-detail'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('decode-token/', DecodeTokenView.as_view(), name='decode-token'),
]
  
