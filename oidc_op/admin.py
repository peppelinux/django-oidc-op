from django.contrib import admin
from django.contrib import messages
from django.utils.translation import ugettext, ugettext_lazy as _

from . models import *


@admin.register(OidcRelyingParty)
class OidcRelyingPartyAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'is_active')
    list_display = ('client_id', 'created', 'is_active')
    search_fields = ('client_id',)
    list_editable = ('is_active',)
    fieldsets = (
             (None, {
                        'fields' : (
                                      ('client_id', 'client_secret',),
                                      ('client_salt',),
                                      ('registration_client_uri',),
                                      ('registration_access_token',),
                                      ('application_type', 'response_types'),
                                      'grant_types',
                                      'token_endpoint_auth_method',
                                      'is_active'
                                    )
                       },
             ),
             ('Temporal values',
                                {
                                'fields' : (
                                            (('client_id_issued_at',)),
                                             'client_secret_expires_at'
                                             ),

                                },
             ),
             ('URIs', {
                         'classes': ('collapse',),
                         'fields' : ('jwks_uri',
                                     'post_logout_redirect_uris',
                                     'redirect_uris'
                                    )
                        },
              ),
        )

    # def save_model(self, request, obj, form, change):
        # res = False
        # msg = ''
        # try:
            # json.dumps(obj.as_pysaml2_mdstore_row())
            # res = obj.validate()
            # super(MetadataStoreAdmin, self).save_model(request, obj, form, change)
        # except Exception as excp:
            # obj.is_valid = False
            # obj.save()
            # msg = str(excp)

        # if not res:
            # messages.set_level(request, messages.ERROR)
            # _msg = _("Storage {} is not valid, if 'mdq' at least a "
                     # "valid url must be inserted. "
                     # "If local: at least a file or a valid path").format(obj.name)
            # if msg: _msg = _msg + '. ' + msg
            # messages.add_message(request, messages.ERROR, _msg)
