import datetime
import logging
import urllib
import pytz

from django.contrib.auth import get_user_model
from oidcendpoint.session import SessionDB
from . models import (OidcRelyingParty,
                      OidcRPResponseType,
                      OidcRPGrantType,
                      OidcRPContact,
                      OidcRPRedirectUri,
                      OidcSession,
                      OidcSessionSso,
                      TIMESTAMP_FIELDS)


logger = logging.getLogger(__name__)


class OidcClientDatabase(object):
    """
    Adaptation of a Django model as if it were a dict
    """
    model = OidcRelyingParty

    def __contains__(self, key):
        if self.model.objects.filter(client_id=key).first():
            return 1

    def __iter__(self):
        values = self.model.objects.all().values_list('client_id')
        self.clients = [cid[0] for cid in values]
        for value in (self.clients):
            yield value

    def get(self, key, excp=None):
        client = self.model.objects.filter(client_id=key,
                                           is_active=True).first()
        if not client:
            return excp
        return client.copy()

    def __getitem__(self, key):
        value = self.get(key)
        if not value:
            raise KeyError
        return value

    def __setitem__(self, key, value):
        dv = value.copy()

        for k,v in dv.items():
            if isinstance(v, int) or isinstance(v, float):
                if k in TIMESTAMP_FIELDS:
                    dt = datetime.datetime.fromtimestamp(v)
                    dv[k] = pytz.utc.localize(dt)

        client = None
        # if the client already exists
        if dv.get('id'):
            client = self.model.objects.\
                        filter(pk=dv['id']).first()

        if dv.get('client_id'):
            client = self.model.objects.\
                        filter(client_id=dv['client_id']).first()

        if not client:
            client_id = dv.pop('client_id')
            client = self.model.objects.create(client_id=client_id)

        for k,v in dv.items():
            setattr(client, k, v)

        client.save()

    def __str__(self):
        return self.__dict__


class OidcSessiondb(SessionDB):
    def __init__(self, db=None):
        self._db = db or OidcSession

    def _get_or_create(self, sid):
        ses = self._db.objects.filter(sid=sid).first()
        if not ses:
            ses = self._db.objects.create(sid=sid)
        return ses

    def __getitem__(self, item):
        _info = self._db.get(item)

        if _info is None:
            sid = self.handler.sid(item)
            _info = self._db.get(sid)

        if _info:
            _si = SessionInfo().from_json(_info)
            return _si
        else:
            return None

    def __setitem__(self, sid, instance):
        try:
            _info = instance.to_json()
        except ValueError:
            _info = json.dumps(instance)

        ses = self._get_or_create(sid)
        ses.session_info = _info
        ses.save()

    def __delitem__(self, key):
        ses = self._db.objects.filter(sid=key)
        if ses:
            ses.delete()
        # self._db.delete(key)

    def keys(self):
        return self._db.keys()


class OidcSSOdb(object):
    def __init__(self, db=None):
        self._db = db or OidcSessionSso

    # def set(self, label, key, value):
        # logger.debug("SSODb set {} - {}: {}".format(label, key, value))
        # _key = KEY_FORMAT.format(label, key)
        # _values = self._db.get(_key)
        # if not _values:
            # self._db.set(_key, [value])
        # else:
            # _values.append(value)
            # self._db.set(_key, _values)

    # def get(self, label, key):
        # _key = KEY_FORMAT.format(label, key)
        # value = self._db.get(_key)
        # logger.debug("SSODb get {} - {}: {}".format(label, key, value))
        # return value

    # def delete(self, label, key):
        # _key = KEY_FORMAT.format(label, key)
        # return self._db.delete(_key)

    # def remove(self, label, key, value):
        # _key = KEY_FORMAT.format(label, key)
        # _values = self._db.get(_key)
        # if _values:
            # _values.remove(value)
        # else:
            # self._db.set(_key, _values)
            # self._db.delete(_key)

    def _get_or_create(self, sid):
        sso = self._db.objects.filter(sid=sid).first()
        if not sso:
            sso = self._db.objects.create(sid=sid)
        return sso


    def map_sid2uid(self, sid, uid):
        """
        Store the connection between a Session ID and a User ID

        :param sid: Session ID
        :param uid: User ID
        """
        sso = self._get_or_create(sid)
        sso.user = get_user_model().objects.get(username=uid)
        sso.save()

    def map_sid2sub(self, sid, sub):
        """
        Store the connection between a Session ID and a subject ID.

        :param sid: Session ID
        :param sub: subject ID
        """
        sso = self._get_or_create(sid)
        sso.sub = sub
        sso.save()

    def get_sids_by_uid(self, uid):
        """
        Return the session IDs that this user is connected to.

        :param uid: The subject ID
        :return: list of session IDs
        """
        sso = self._db.objects.filter(user__username=uid).first()
        if sso:
            return [sso.sid]
        return []

    def get_sids_by_sub(self, sub):
        sso = self._db.objects.filter(sub=sub).first()
        if sso:
            return [sso.sid]
        return []

    def get_sub_by_sid(self, sid):
        sso = self._db.objects.filter(sid=sid).first()
        if sso:
            return sso.sub

    def get_uid_by_sid(self, sid):
        """
        Find the User ID that is connected to a Session ID.

        :param sid: A Session ID
        :return: A User ID, always just one
        """
        sso = self._db.objects.filter(sid=sid).first()
        if sso and sso.user:
            return sso.user.username

    def get_subs_by_uid(self, uid):
        """
        Find all subject identifiers that is connected to a User ID.

        :param uid: A User ID
        :return: A set of subject identifiers
        """
        sso = self._db.objects.filter(user__username=uid).first()
        if sso and sso.sub:
            return [sso.sub]
        return []

    def remove_sid2sub(self, sid, sub):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param sub: Subject identifier
´       """
        sso = self._db.objects.filter(sub=sub, sid=sid)
        if sso:
            sso.delete()

    def remove_sid2uid(self, sid, uid):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param uid: User identifier
´       """
        sso = self._db.objects.filter(user__username=uid, sid=sid)
        if sso:
            sso.delete()

    def remove_session_id(self, sid):
        """
        Remove all references to a specific Session ID

        :param sid: A Session ID
        """
        sso = self._db.objects.filter(sid=sid)
        if sso:
            sso.delete()

    def remove_uid(self, uid):
        """
        Remove all references to a specific User ID

        :param uid: A User ID
        """
        sso = self._db.objects.filter(user__username=uid)
        if sso:
            sso.delete()

    def remove_sub(self, sub):
        """
        Remove all references to a specific Subject ID

        :param sub: A Subject ID
        """
        sso = self._db.objects.filter(sub=sub)
        if sso:
            sso.delete()
