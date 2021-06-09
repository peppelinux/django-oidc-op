from django.contrib import admin

from .models import PersistentId


class PersistentIdInline(admin.TabularInline):
    model = PersistentId
    extra = 0
