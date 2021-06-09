import json
import logging

from django import forms
from django.contrib import admin
from django.contrib.sessions.models import Session
from django.utils.safestring import mark_safe

from . models import OidcIssuedToken
from . models import OidcRPContact
from . models import OidcRPRedirectUri
from . models import OidcRPGrantType
from . models import OidcRPResponseType
from . models import OidcRPScope
from . models import OidcRelyingParty
from . models import OidcSession

logger = logging.getLogger(__name__)


class OidcRPContactModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPContact
        fields = ('__all__')


class OidcRPContactInline(admin.TabularInline):
    model = OidcRPContact
    form = OidcRPContactModelForm
    extra = 0


class OidcRPRedirectUriModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPRedirectUri
        fields = ('__all__')


class OidcRPRedirectUriInline(admin.TabularInline):
    model = OidcRPRedirectUri
    form = OidcRPRedirectUriModelForm
    extra = 0


class OidcRPGrantTypeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPGrantType
        fields = ('__all__')


class OidcRPGrantTypeInline(admin.TabularInline):
    model = OidcRPGrantType
    form = OidcRPGrantTypeModelForm
    extra = 0


class OidcRPResponseTypeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPResponseType
        fields = ('__all__')


class OidcRPResponseTypeInline(admin.TabularInline):
    model = OidcRPResponseType
    form = OidcRPResponseTypeModelForm
    extra = 0


class OidcRPScopeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPScope
        fields = ('__all__')


class OidcRPScopeInline(admin.TabularInline):
    model = OidcRPScope
    form = OidcRPScopeModelForm
    extra = 0


@admin.register(OidcRelyingParty)
class OidcRelyingPartyAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'is_active',
                   'client_id_issued_at', 'client_secret_expires_at')
    list_display = ('client_id', 'created',
                    'last_seen', 'is_active')
    search_fields = ('client_id',)
    list_editable = ('is_active',)
    inlines = (OidcRPScopeInline,
               OidcRPResponseTypeInline,
               OidcRPGrantTypeInline,
               OidcRPContactInline,
               OidcRPRedirectUriInline)
    fieldsets = (
        (None, {
            'fields': (
                ('client_id', 'client_secret',),
                ('client_salt', 'jwks_uri'),
                ('registration_client_uri',),
                ('registration_access_token',),
                ('application_type',
                 'token_endpoint_auth_method'),
                ('is_active', )
            )
        },
        ),
        ('Temporal values',
         {
             'fields': (
                 (('client_id_issued_at',
                   'client_secret_expires_at',
                   'last_seen')),

             ),

         },
         ),
    )


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):  # pragma: no cover
    def _session_data(self, obj):
        return obj.get_decoded()
    list_display = ['session_key', '_session_data', 'expire_date']


@admin.register(OidcIssuedToken)
class OidcIssuedTokenAdmin(admin.ModelAdmin):
    search_fields = ('value', 'session__user__username')
    list_display = ['session', 'type', 'created']
    list_filter = ('issued_at', 'expires_at', 'revoked', 'type')
    readonly_fields = (
        "type",
        "issued_at",
        "expires_at",
        "not_before",
        "revoked",
        "value",
        "usage_rules",
        "used",
        "based_on",
        "session",
        "uid"
    )


@admin.register(OidcSession)
class OidcSessionAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'expires_at')
    list_display = ('user', 'user_uid', 'client',
                    'grant_uid', 'created', 'expires_at')
    search_fields = ('user__username', 'client__client_id')
    readonly_fields = ('user_uid', 'user', 'client',
                       'sub', 'sid', 'sid_encrypted', 'key', 'salt',
                       'created', 'expires_at',
                       'user_session_info_preview',
                       'client_session_info_preview',
                       'grant_preview'
                       )

    fieldsets = (
        (None, {
            'fields': (
                ('client', ),
                ('user_uid',),
                ('sub', ),
                ('sid',),
                ('sid_encrypted',),
                ('key',),
                ('salt',),
                ('created',),
                ('expires_at',),
            )
        },
        ),

        ('User session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('user_session_info_preview'),
             )

         },
         ),

        ('Client session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('client_session_info_preview'),
             )

         },
         ),

        ('Grant session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('grant_preview'),
             )
         },
         ),
    )

    def user_session_info_preview(self, obj):
        dumps = json.dumps(obj.user_session_info, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    user_session_info_preview.short_description = 'User Session Info'

    def client_session_info_preview(self, obj):
        dumps = json.dumps(obj.client_session_info, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    client_session_info_preview.short_description = 'Client Session Info'

    def grant_preview(self, obj):
        dumps = json.dumps(obj.grant, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    grant_preview.short_description = 'Grant'

    class Media:
        js = ('js/textarea_autosize.js',)
