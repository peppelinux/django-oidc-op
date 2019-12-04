from . models import (OidcRelyingParty,
                     )


class OidcClientDatabase(object):
    model = OidcRelyingParty

    def __getitem__(self, value):
        return self.model.objects.filter(client_id=value,
                                         is_active=True).first()
