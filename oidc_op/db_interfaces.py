import datetime
import json
import logging
import re
import pytz
import urllib


from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from oidcendpoint.session import (SessionDB,
                                  public_id,
                                  pairwise_id)
from . models import (OidcRelyingParty,
                      OidcRPResponseType,
                      OidcRPGrantType,
                      OidcRPContact,
                      OidcRPRedirectUri,
                      OidcSession,
                      OidcSessionSso,
                      TIMESTAMP_FIELDS,
                      is_state,
                      is_sid,
                      is_sub,
                      is_code)


logger = logging.getLogger(__name__)


class OidcClientDb(object):
    """
    Adaptation of a Django model as if it were a dict
    """
    model = OidcRelyingParty

    def __init__(self, *args, **kwargs):
        pass

    def __contains__(self, key):
        if self.model.objects.filter(client_id=key).first():
            return 1

    def __iter__(self):
        values = self.model.objects.all().values_list('client_id')
        self.clients = [cid[0] for cid in values]
        for value in (self.clients):
            yield value

    def get(self, key, excp=None, as_obj=False):
        client = self.model.objects.filter(client_id=key,
                                           is_active=True).first()
        if not client:
            return excp

        # set last_seen
        client.last_seen = timezone.localtime()
        client.save()
        if as_obj: return client
        return client.copy()

    def __getitem__(self, key):
        value = self.get(key)
        if not value:
            raise KeyError
        return value

    def keys(self):
        return self.model.objects.values_list('client_id', flat=True)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def set(self, key, value):
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


class OidcSessionDb(SessionDB):
    """
    Adaptation of a Django model as if it were a dict

    This class acts like a NoSQL storage but stores informations
    into a pure Django DB model
    """

    def __init__(self, conf_db=None, session_db=None, sso_db=None, cdb=None):
        self.conf_db = conf_db
        self.db = session_db or OidcSession
        self.sso_db = sso_db or OidcSessionSso
        self.cdb = cdb or OidcClientDb()

    def get_by_sid(self, value):
        session = self.db.get_by_sid(value)
        if session:
            return session

    def get_by_state(self, value):
        session = self.db.objects.filter(state=value)
        if session:
            return session.last()

    def create_by_state(self, state):
        return self.db.objects.create(state=state)

    def _get_or_create(self, sid):
        ses = self.db.get_by_sid(sid)
        #  if not ses:
            #  sso = self.sso_db.objects.get(sso__sid=sid)
            #  ses = self.db.objects.create(sso=sso)
        return ses

    def __contains__(self, key):
        query = self._get_q(key)
        if self.db.objects.filter(query).first():
            return 1

    def __iter__(self):
        self.elems = self.keys()
        for value in (self.elems):
            yield value

    def get(self, key, excp=None):
        if is_sid(key):
            elem = self.db.get_by_sid(key)
        elif is_code(key):
            elem = self.db.objects.filter(code=key).last()
        else:
            # state is unpredictable, it's client side.
            elem = self.db.objects.filter(state=key).last()

        if not elem:
            return
        elif elem.sid and elem.sid[-1] == key:
            return json.loads(elem.session_info)
        elif elem.state == key:
            return elem.sso.sid

    def set_session_info(self, info_dict):
        session = self.db.objects.get(state=info_dict['authn_req']['state'])
        session.session_info = json.dumps(info_dict)
        session.code = info_dict.get('code')
        authn_event = info_dict.get('authn_event')
        valid_until = authn_event.get('valid_until')
        if valid_until:
            dt = datetime.datetime.fromtimestamp(valid_until)
            session.valid_until = pytz.utc.localize(dt)

        client_id = info_dict.get('client_id')
        session.client = self.cdb.get(key=client_id, as_obj=True)
        session.save()


    def set(self, key, value):
        if is_sid(key):
            # info_dict = {'code': 'Z0FBQUFBQmZESFowazFBWWJteTNMOTZQa25KZmV0N1U1VzB4VEZCVEN3SThQVnVFRWlSQ2FrODhpb3Yyd3JMenJQT01QWGpuMnJZQmQ4YVh3bF9sbUxqMU43VG1RQ01BbW9JdV8tbTNNSzREMUk2U2N4YXVwZ3ZWQ1ZvbXdFanRsbWJIaWQyVWZON0N5LU9mUlhZUGgwdFRDQkpRZ3dSR0lVQjBBT0s4OHc3REJOdUlPUGVOUU9ZRlZvU3FBdVU2LThUUWNhRDVocl9QWEswMmo3Y2VtLUNvWklsX0ViN1NfWFRJWksxSXhxNVVNQW9ySngtc2RCST0=', 'oauth_state': 'authz', 'client_id': 'Mz2LUfvqCbRQ', 'authn_req': {'redirect_uri': 'https://127.0.0.1:8099/authz_cb/django_oidc_op', 'scope': 'openid profile email address phone', 'response_type': 'code', 'nonce': 'mpuLL5IxgDvFDGAqlE05LwHO', 'state': 'eOzFkkGFHLT16zO6SqpOmc2rv6DZmf3g', 'code_challenge': 'lAs7I04g1Qh8mhTG8wxV0BfmrhzrSrl1ASp04C3Zmog', 'code_challenge_method': 'S256', 'client_id': 'Mz2LUfvqCbRQ'}, 'authn_event': {'uid': 'wert', 'salt': 'fc7AGQ==', 'authn_info': 'oidcendpoint.user_authn.authn_context.INTERNETPROTOCOLPASSWORD', 'authn_time': 1594652276, 'valid_until': 1594655876}}
            info_dict = value
            self.set_session_info(info_dict)
        logger.debug('Session DB - set - {}'.format(session.copy()))


    def delete(self, key):
        """already called in its childs, here for debugging purpose
        """
        if is_state(key):
            pass
            #  self.db.objects.filter(**state_dict).delete()
        elif is_sid(key):
            #  self.db.objects.filter(sso__sid=key).delete()
            pass
        else:
            #  import pdb; pdb.set_trace()
            pass

    def __getitem__(self, item):
        #  import pdb; pdb.set_trace()
        q = _get_q(item)
        _info = self.db.objects.filter(q).first()
        if not _info:
            sid = self.handler.sid(item)
            _info = self.db.objects.get(sso__sid=sid)

        if _info:
            import pdb; pdb.set_trace()
            return SessionInfo().from_json(_info.session_info)

    def __setitem__(self, sid, instance):
        if is_sid(sid):
            try:
                _info = instance.to_json()
            except ValueError as e:
                _info = json.dumps(instance)
            except AttributeError as e:
                # it's a dict
                _info = instance

            ses = self._get_or_create(sid)
            self.set_session_info(instance)
        else:
            logger.error('{} tries __setitem__ {} in {}'.format(sid,
                                                                instance,
                                                                self.__class__.__name__))

    def __delitem__(self, key):
        if is_sid(key):
            ses = self.db.get_by_sid(key)
            if ses:
                ses.delete()

    def keys(self):
        #  import pdb; pdb.set_trace()
        elems = self.db.objects.all()
        states = elems.values_list('state')
        sids = elems.values_list('sso__sid')
        return [el[0] for el in states+sids]


class OidcSsoDb(object):
    """
    Adaptation of a Django model as if it were a dict

    This class acts like a NoSQL storage but stores informations
    into a pure Django DB model
    """
    def __init__(self, db_conf={}, db=None, session_handler=None):
        self._db = db or OidcSessionSso
        self._db_conf = db_conf
        self.session_handler = session_handler or db_conf.get('session_hanlder') or OidcSessionDb()

    def _get_or_create(self, sid):
        sso = self._db.objects.filter(sid=sid).first()
        if not sso:
            sso = self._db.objects.create(sid=sid)
        return sso

    def __setitem__(self, k, value):
        if isinstance(value, dict):
            if value.get('state'):
                session = self.session_handler.create_by_state(k)
                sid = session.oidcsessionsid_set.create(session=session,
                                                        sid=value['state'][0] \
                                                        if isinstance(value['state'], list) else value)
                sso = self._db.objects.create()
                session.sso = sso
                session.save()
        else:
            # it would be quite useless for this implementation ...
            # k = '81c58c4037ab1939423ab4fb8b472fdd5fc3a3939e4debc81f52ed37'
            # value = <OidcSessionSso: user: wert - sub: None>
            pass

    def set(self, k, v):
        logging.info('{}:{} - already there'.format(k, v))

    def get(self, k, default):
        session = self.session_handler.get_by_state(k)
        if session:
            return session

        if is_sub(k):
            # sub
            return self._db.objects.filter(sub=k).last() or {}
        elif is_sid(k):
            # sid
            session = self.session_handler.get_by_sid(k)
            return session.sso if session else {}
        else:
            logger.debug(("{} can't find any attribute "
                          "with this name as attribute: {}").format(self, k))
            user = get_user_model().objects.filter(username=k).first()
            if user:
                logger.debug('Tryng to match to a username: Found {}'.format(user))
                return self._db.objects.filter(user=user).last()
            else:
                return {}

    def __delitem__(self, name):
        self.delete(name)

    def delete(self, name):
        if is_sid(name):
            session = self.session_handler.get_by_sid(name)
            if session: session.delete()

    # DEPRECATED from v0.13.0 - to be removed
    #  def map_sid2uid(self, sid, uid):
        #  """
        #  Store the connection between a Session ID and a User ID

        #  :param sid: Session ID
        #  :param uid: User ID
        #  """
        #  sso = self._get_or_create(sid)
        #  sso.user = get_user_model().objects.get(username=uid)
        #  sso.save()

    #  def map_sid2sub(self, sid, sub):
        #  """
        #  Store the connection between a Session ID and a subject ID.

        #  :param sid: Session ID
        #  :param sub: subject ID
        #  """
        #  sso = self._get_or_create(sid)
        #  sso.sub = sub
        #  sso.save()

    #  def get_sids_by_uid(self, uid):
        #  """
        #  Return the session IDs that this user is connected to.

        #  :param uid: The subject ID
        #  :return: list of session IDs
        #  """
        #  sso = self._db.objects.filter(user__username=uid).first()
        #  if sso:
            #  return [sso.sid]
        #  return []

    #  def get_sids_by_sub(self, sub):
        #  sso = self._db.objects.filter(sub=sub).first()
        #  if sso:
            #  return [sso.sid]
        #  return []

    #  def get_sub_by_sid(self, sid):
        #  sso = self._db.objects.filter(sid=sid).first()
        #  if sso:
            #  return sso.sub

    #  def get_uid_by_sid(self, sid):
        #  """
        #  Find the User ID that is connected to a Session ID.

        #  :param sid: A Session ID
        #  :return: A User ID, always just one
        #  """
        #  sso = self._db.objects.filter(sid=sid).first()
        #  if sso and sso.user:
            #  return sso.user.username

    #  def get_subs_by_uid(self, uid):
        #  """
        #  Find all subject identifiers that is connected to a User ID.

        #  :param uid: A User ID
        #  :return: A set of subject identifiers
        #  """
        #  sso = self._db.objects.filter(user__username=uid).first()
        #  if sso and sso.sub:
            #  return [sso.sub]
        #  return []

    #  def remove_sid2sub(self, sid, sub):
        #  """
        #  Remove the connection between a session ID and a Subject

        #  :param sid: Session ID
        #  :param sub: Subject identifier
#  ´       """
        #  sso = self._db.objects.filter(sub=sub, sid=sid)
        #  if sso:
            #  sso.delete()

    #  def remove_sid2uid(self, sid, uid):
        #  """
        #  Remove the connection between a session ID and a Subject

        #  :param sid: Session ID
        #  :param uid: User identifier
#  ´       """
        #  sso = self._db.objects.filter(user__username=uid, sid=sid)
        #  if sso:
            #  sso.delete()

    #  def remove_session_id(self, sid):
        #  """
        #  Remove all references to a specific Session ID

        #  :param sid: A Session ID
        #  """
        #  sso = self._db.objects.filter(sid=sid)
        #  if sso:
            #  sso.delete()

    #  def remove_uid(self, uid):
        #  """
        #  Remove all references to a specific User ID

        #  :param uid: A User ID
        #  """
        #  sso = self._db.objects.filter(user__username=uid)
        #  if sso:
            #  sso.delete()

    #  def remove_sub(self, sub):
        #  """
        #  Remove all references to a specific Subject ID

        #  :param sub: A Subject ID
        #  """
        #  sso = self._db.objects.filter(sub=sub)
        #  if sso:
            #  sso.delete()
