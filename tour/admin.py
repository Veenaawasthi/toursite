from django.contrib import admin
from . import models

# Register your models here.

admin.site.register(models.Query)
admin.site.register(models.Itinerary)
admin.site.register(models.UserMetrics)
admin.site.register(models.User)
admin.site.register(models.Day)
admin.site.register(models.Hotel)
admin.site.register(models.QuotationSlab)



