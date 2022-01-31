import base64
import logging
import json
import os
import sys
import urllib

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import (HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseForbidden,
                         HttpResponseRedirect,
                         JsonResponse)
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from oidcop.authn_event import create_authn_event
from oidcop.exception import InvalidClient
from oidcop.exception import UnAuthorizedClient
from oidcop.exception import UnknownClient
from oidcmsg.oidc import AuthorizationErrorResponse
from oidcop.oidc.token import Token
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from urllib.parse import urlparse

from . application import oidcop_app
from . decorators import fill_cdb_by_request, prepare_oidc_endpoint, debug_request
from . exceptions import InconsinstentSessionDump
from . models import OidcRelyingParty, OidcSession, OidcIssuedToken


logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


def _add_cookie(resp, cookie_spec):
    kwargs = {
        k: v
        for k, v in cookie_spec.items()
        if k not in ('name',)
    }
    kwargs["path"] = "/"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp, cookie_spec):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


def _check_session_dump_consistency(endpoint_name, ec, session):
    if ec.endpoint_context.session_manager.dump() != session:
        logger.critical(
            ec.endpoint_context.session_manager.dump(),
            session
        )
        ec.endpoint_context.session_manager.flush()
        raise InconsinstentSessionDump(endpoint_name)


def do_response(request, endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)
    _response_placement = info.get('response_placement')
    if not _response_placement:
        _response_placement = endpoint.response_placement

    info_response = info['response']

    if settings.DEBUG:
        # Debugging things
        try:
            response_params = json.dumps(json.loads(info_response), indent=2)
            logger.debug('Response params: {}\n'.format(response_params))
        except Exception:
            url, args = urllib.parse.splitquery(info_response)
            response_params = urllib.parse.parse_qs(args)
            resp = json.dumps(response_params, indent=2)
            logger.debug('Response params: {}\n{}\n\n'.format(url, resp))
        # end debugging

    if error:
        if _response_placement == 'body':
            logger.error('Error Response [Body]: {}'.format(info_response))
            resp = HttpResponse(info_response, status=400)
        else:  # _response_placement == 'url':
            logger.debug('Redirect to: {}'.format(info_response))
            resp = HttpResponseRedirect(info_response)
    else:
        if _response_placement == 'body':
            # logger.debug('Response [Body]: {}'.format(info_response))
            resp = HttpResponse(info_response, status=200)
        else:  # _response_placement == 'url':
            # logger.debug('Redirect to: {}'.format(info_response))
            resp = HttpResponseRedirect(info_response)

    for key, value in info['http_headers']:
        # set response headers
        resp[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    ec = oidcop_app.endpoint_context
    ses_man_dump = ec.endpoint_context.session_manager.dump()

    # session db mngmtn
    if endpoint.__class__.__name__ in ('Authorization',
                                       'Token',
                                       'UserInfo'):
        try:
            OidcSession.load(ses_man_dump)
        except InconsinstentSessionDump as e:
            logger.critical(e)
            ec.endpoint_context.session_manager.flush()
            return JsonResponse(json.dumps({
                'error': 'invalid_request',
                'error_description': str(e),
                'method': request.method
            }), safe=False, status=500)
        else:
            #  logger.warning(endpoint.__class__.__name__)
            _check_session_dump_consistency(endpoint.__class__.__name__,
                                            ec,
                                            ses_man_dump)
        ec.endpoint_context.session_manager.flush()
    return resp


def _get_http_info(request):
    http_info = {
        "headers": {
            k.lower(): v
            for k, v in request.headers.items()
            if k not in IGNORED_HEADERS
        },
        "method": request.method,
        "url": request.build_absolute_uri(),
        # name is not unique
        "cookie": [
            {"name": k, "value": v} for k, v in request.COOKIES.items()
        ]
    }
    return http_info


def _get_http_data(request, http_info):
    data = {}
    _meth = getattr(request, request.method)
    data = {k: v for k, v in _meth.items()}

    if not data and request.body:
        data = json.loads(request.body)

    return data


def service_endpoint(request, endpoint):
    """
    TODO: documentation here
    """
    logger.info('Request at the "{}" endpoint'.format(endpoint.name))

    http_info = _get_http_info(request)
    data = _get_http_data(request, http_info)
    req_args = endpoint.parse_request(data, http_info=http_info)

    try:
        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info
            )
        else:
            args = endpoint.process_request(req_args, http_info=http_info)
    except (InvalidClient, UnknownClient, UnAuthorizedClient) as err:
        logger.error(err)
        return JsonResponse(json.dumps({
            'error': 'unauthorized_client',
            'error_description': str(err)
        }), safe=False, status=400)
    except Exception as err:
        logger.error(err)
        return JsonResponse(json.dumps({
            'error': 'invalid_request',
            'error_description': str(err),
            'method': request.method
        }), safe=False, status=400)

    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        return JsonResponse(req_args.__dict__, status=400)
    elif 'redirect_location' in args:
        return HttpResponseRedirect(args['redirect_location'])
    elif 'http_response' in args:
        return HttpResponse(args['http_response'], status=200)

    return do_response(request, endpoint, req_args, **args)


def well_known(request, service):
    """
    /.well-known/<service>
    """
    _name = sys._getframe().f_code.co_name
    debug_request(f'{_name}', request)

    if service == 'openid-configuration':
        _endpoint = oidcop_app.endpoint_context.endpoint['provider_config']
    # TODO fedservice integration here
    # if service == 'openid-federation':
    #     _endpoint = oidcop_app.endpoint_context.endpoint['provider_info']
    elif service == 'webfinger':
        _endpoint = oidcop_app.endpoint_context.endpoint['webfinger']
    else:
        return HttpResponseBadRequest('Not supported', status=400)

    return service_endpoint(request, _endpoint)


@csrf_exempt
@prepare_oidc_endpoint
def registration(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['registration']
    response = service_endpoint(request, _endpoint)
    # update db
    OidcRelyingParty.import_from_cdb(
        oidcop_app.endpoint_context.endpoint_context.cdb
    )
    return response


@csrf_exempt
@prepare_oidc_endpoint
@fill_cdb_by_request
def registration_read(request):
    return service_endpoint(
        request,
        oidcop_app.endpoint_context.endpoint['registration_read']
    )


def _fill_cdb_by_client(client):
    ec = oidcop_app.endpoint_context
    ec.endpoint_context.cdb = {
        client.client_id: client.serialize()
    }


@prepare_oidc_endpoint
@fill_cdb_by_request
def authorization(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['authorization']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def verify_user(request):
    """csrf is not needed because it uses oidc token in the post
    """
    _name = sys._getframe().f_code.co_name
    debug_request(f'{_name}', request)

    token = request.POST.get('token')
    if not token:  # pragma: no cover
        return HttpResponse('Access forbidden: invalid token.', status=403)

    ec = oidcop_app.endpoint_context
    authn_method = ec.endpoint_context.authn_broker.get_method_by_id('user')

    kwargs = dict([(k, v) for k, v in request.POST.items()])
    user = authn_method.verify(**kwargs)
    if not user:
        return HttpResponse('Authentication failed', status=403)

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    # salt size can be customized in settings.OIDC_OP_AUTHN_SALT_SIZE
    salt_size = getattr(settings, 'OIDC_OP_AUTHN_SALT_SIZE', 4)
    authn_event = create_authn_event(
        uid=user.username,
        salt=base64.b64encode(os.urandom(salt_size)).decode(),
        authn_info=auth_args['authn_class_ref'],
        authn_time=auth_args['iat']
    )

    endpoint = oidcop_app.endpoint_context.endpoint['authorization']
    client_id = authz_request["client_id"]
    _token_usage_rules = endpoint.server_get(
        "endpoint_context").authn_broker.get_method_by_id('user')

    session_manager = ec.endpoint_context.session_manager
    _session_id = session_manager.create_session(
        authn_event=authn_event,
        auth_req=authz_request,
        user_id=user.username,
        client_id=client_id,
        token_usage_rules=_token_usage_rules
    )

    try:
        _args = endpoint.authz_part2(user=user.username,
                                     session_id=_session_id,
                                     request=authz_request,
                                     authn_event=authn_event)
    except ValueError as excp:
        msg = 'Something went wrong with your Session ... {}'.format(excp)
        return HttpResponse(msg, status=403)

    if isinstance(_args, ResponseMessage) and 'error' in _args:
        return HttpResponse(_args.to_json(), status=400)
    elif isinstance(_args.get('response_args'), AuthorizationErrorResponse):
        rargs = _args.get('response_args')
        logger.error(rargs)
        return HttpResponse(rargs.to_json(), status=400)

    response = do_response(request, endpoint, authz_request, **_args)
    return response


def _get_session_by_token(request):
    bearer = request.META.get('HTTP_AUTHORIZATION')
    token = None

    if bearer and not request.POST:
        token = OidcIssuedToken.objects.filter(
            value=bearer.split(' ')[1]
        ).first()
    elif all((request.POST.get('refresh_token'),
              request.POST.get('grant_type') == 'refresh_token')):
        token = OidcIssuedToken.objects.filter(
            type=request.POST['grant_type'],
            value=request.POST['refresh_token']
        ).first()
    elif request.POST.get('grant_type') == 'authorization_code':
        token = OidcIssuedToken.objects.filter(
            type=request.POST['grant_type'],
            value=request.POST.get('code')
        ).first()
    elif request.POST.get('token_type_hint'):
        # token introspection
        token = OidcIssuedToken.objects.filter(
            type=request.POST['token_type_hint'],
            value=request.POST['token']
        ).first()
    elif request.GET.get('id_token_hint') or request.POST.get('id_token_hint'):
        _id_token_hint = request.GET.get('id_token_hint') or request.POST.get('id_token_hint')
        token = OidcIssuedToken.objects.filter(
            type='id_token',
            value=_id_token_hint
        ).first()
    else:
        raise PermissionDenied()

    if token:
        return token.session
    else:
        raise PermissionDenied()


@csrf_exempt
@prepare_oidc_endpoint
@fill_cdb_by_request
def token(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['token']
    session = _get_session_by_token(request).serialize()
    if session:
        ec.endpoint_context.session_manager.load(session)
    _check_session_dump_consistency('token', ec, session)

    response = service_endpoint(request, _endpoint)
    return response


@csrf_exempt
@prepare_oidc_endpoint
def userinfo(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['userinfo']

    session = _get_session_by_token(request)
    _fill_cdb_by_client(session.client)
    session = session.serialize()

    if session:
        ec.endpoint_context.session_manager.load(session)
    _check_session_dump_consistency('userinfo', ec, session)

    return service_endpoint(request, _endpoint)


@csrf_exempt
@prepare_oidc_endpoint
def introspection(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['introspection']

    session = _get_session_by_token(request)
    _fill_cdb_by_client(session.client)
    ec.endpoint_context.cdb
    session = session.serialize()

    if session:
        ec.endpoint_context.session_manager.load(session)
    _check_session_dump_consistency('introspection', ec, session)

    return service_endpoint(request, _endpoint)


########
# LOGOUT
########
@prepare_oidc_endpoint
def session_endpoint(request):
    ec = oidcop_app.endpoint_context
    _endpoint = ec.endpoint['session']
    session = _get_session_by_token(request)
    _fill_cdb_by_client(session.client)
    session = session.serialize()
    if session:
        ec.endpoint_context.session_manager.load(session)
    _check_session_dump_consistency('session', ec, session)
    try:
        res = service_endpoint(request, _endpoint)
        return res
    except Exception:
        ec.endpoint_context.session_manager.flush()
        return HttpResponseForbidden()


# TODO - not supported yet with session manager storage

def check_session_iframe(request):
    if request.method == 'GET':
        req_args = request.GET
    elif request.method == 'POST':
        req_args = json.loads(request.POST)
    else:
        req_args = dict([(k, v) for k, v in request.body.items()])

    if req_args:
        # will contain client_id and origin
        if req_args['origin'] != oidcop_app.endpoint_context.conf['issuer']:
            return 'error'
        if req_args['client_id'] != oidcop_app.endpoint_context.cdb:
            return 'error'
        return 'OK'

    logger.debug('check_session_iframe: {}'.format(req_args))
    res = render(request, template_name='check_session_iframe.html')
    return res


@csrf_exempt
def rp_logout(request):
    _name = sys._getframe().f_code.co_name
    debug_request(f'{_name}', request)

    _endp = oidcop_app.endpoint_context.endpoint['session']
    _info = _endp.unpack_signed_jwt(request.POST['sjwt'])
    alla = None

    _iframes = _endp.do_verified_logout(alla=alla, **_info)
    if _iframes:
        d = dict(frames=" ".join(_iframes),
                 size=len(_iframes),
                 timeout=5000,
                 postLogoutRedirectUri=_info['redirect_uri'])
        res = render(request, 'frontchannel_logout.html', d)

    else:
        res = HttpResponseRedirect(_info['redirect_uri'])
        try:
            _endp.kill_cookies()
        except AttributeError:
            logger.debug('Cookie not implemented or not working.')
    return res


def verify_logout(request):
    _name = sys._getframe().f_code.co_name
    debug_request(f'{_name}', request)

    part = urlparse(oidcop_app.endpoint_context.conf['issuer'])
    d = dict(op=part.hostname,
             do_logout='rp_logout',
             sjwt=request.GET['sjwt'] or request.POST['sjwt'])
    return render(request, 'logout.html', d)


def post_logout(request):
    _name = sys._getframe().f_code.co_name
    debug_request(f'{_name}', request)
    return render(request, 'post_logout.html')
