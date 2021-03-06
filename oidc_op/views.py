import base64
import logging
import json
import os
import urllib

from django.conf import settings
from django.http import (HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseRedirect,
                         JsonResponse)
from django.http.request import QueryDict
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.exception import FailedAuthentication
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.exception import UnAuthorizedClientScope # experimental
from oidcendpoint.exception import InvalidClient
from oidcendpoint.exception import UnknownClient
from oidcendpoint.oidc.token import AccessToken
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from urllib import parse as urlib_parse
from urllib.parse import urlparse

from pprint import pformat

from . application import oidcendpoint_application
oidcendpoint_app = oidcendpoint_application()

logger = logging.getLogger(__name__)


# to be evaluated in a pure Django Session
# def _add_cookie(resp, cookie_spec):
    # for key, _morsel in cookie_spec.items():
        # kwargs = {'value': _morsel.value}
        # for param in ['expires', 'path', 'comment', 'domain', 'max-age',
                      # 'secure',
                      # 'version']:
            # if _morsel[param]:
                # kwargs[param] = _morsel[param]
        # resp.set_cookie(key, **kwargs)


# def add_cookie(resp, cookie_spec):
    # if isinstance(cookie_spec, list):
        # for _spec in cookie_spec:
            # _add_cookie(resp, _spec)


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)
    _response_placement = info.get('response_placement')
    if not _response_placement:
        _response_placement = endpoint.response_placement

    info_response = info['response']
    # Debugging things
    try:
        response_params = json.dumps(json.loads(info_response), indent=2)
        logger.debug('Response params: {}\n'.format(response_params))
    except:
        url, args = urllib.parse.splitquery(info_response)
        response_params = urllib.parse.parse_qs(args)
        resp = json.dumps(response_params, indent=2)
        logger.debug('Response params: {}\n{}\n\n'.format(url, resp))
    # end debugging

    if error:
        if _response_placement == 'body':
            logger.debug('Error Response [Body]: {}'.format(info_response))
            resp = HttpResponse(info_response, status=400)
        else:  # _response_placement == 'url':
            logger.debug('Redirect to: {}'.format(info_response))
            resp = HttpResponseRedirect(info_response)
    else:
        if _response_placement == 'body':
            #logger.debug('Response [Body]: {}'.format(info_response))
            resp = HttpResponse(info_response, status=200)
        else:  # _response_placement == 'url':
            #logger.debug('Redirect to: {}'.format(info_response))
            resp = HttpResponseRedirect(info_response)

    for key, value in info['http_headers']:
        # set response headers
        resp[key] = value

    # if 'cookie' in info:
        # add_cookie(resp, info['cookie'])

    return resp


def fancy_debug(request):
    """
    fancy logging of JWT things
    """
    _headers = json.dumps(dict(request.headers), indent=2)
    logger.debug('Request Headers: {}\n\n'.format(_headers))

    _get = json.dumps(dict(request.GET), indent=2)
    if request.GET:
        logger.debug('Request arguments GET: {}\n'.format(_get))
    if request.POST or request.body:
        _post = request.POST or request.body
        if isinstance(_post, bytes):
            _post = json.dumps(json.loads(_post.decode()), indent=2)
        elif isinstance(_post, QueryDict):
            _post = json.dumps({k:v for k,v in _post.items()},
                               indent=2)
        logger.debug('Request arguments POST: {}\n'.format(_post))


def service_endpoint(request, endpoint):
    """
    TODO: documentation here
    """
    logger.info('\n\nRequest at the "{}" endpoint'.format(endpoint.endpoint_name))
    if logger.level == 0:
        fancy_debug(request)

    authn = request.headers.get('Authorization', {})
    pr_args = {'auth': authn}

    if request.method == 'GET':
        data = {k:v for k,v in request.GET.items()}
    elif request.body:
        data = request.body \
               if isinstance(request.body, str) else \
               request.body.decode()
        #<oidcendpoint.oidc.token.AccessToken object at 0x7fd626329d68>
        if authn:
            data = {k:v[0] for k,v in urlib_parse.parse_qs(data).items()}
    else:
        data = {k:v for k,v in request.POST.items()}

    # for .well-known resources like provider-config no data are submitted
    # if not data:
    #   ... not possible in this implementation

    try:
        req_args = endpoint.parse_request(data, **pr_args)
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

    if request.COOKIES:
        kwargs = {'cookie': request.COOKIES}
    else:
        kwargs = {}

    try:
        if isinstance(endpoint, AccessToken):
            args = endpoint.process_request(AccessTokenRequest(**req_args),
                                            **kwargs)
        else:
            args = endpoint.process_request(req_args, **kwargs)
    except UnAuthorizedClientScope as e:
        logger.exception(e)
        _msg = 'UnAuthorized scopes to this RP: {}'.format(req_args['scope'])
        return JsonResponse({"error_description": _msg,
                             "error": "invalid_scope"}, status=400)
    except Exception as e:
        logger.exception(e)
        return HttpResponse('Error', status=500)

    # logger.debug('Response args: {}'.format(args))
    if 'redirect_location' in args:
        return HttpResponseRedirect(args['redirect_location'])
    if 'http_response' in args:
        return HttpResponse(args['http_response'], status=200)

    return do_response(endpoint, req_args, **args)


def well_known(request, service):
    """
    /.well-known/<service>
    """
    if service == 'openid-configuration':
        _endpoint = oidcendpoint_app.endpoint_context.endpoint['provider_config']
    # TODO fedservice integration here
    # if service == 'openid-federation':
    #     _endpoint = oidcendpoint_app.endpoint_context.endpoint['provider_info']
    elif service == 'webfinger':
        _endpoint = oidcendpoint_app.endpoint_context.endpoint['webfinger']
    else:
        return HttpResponseBadRequest('Not supported', status=400)

    return service_endpoint(request, _endpoint)


@csrf_exempt
def registration(request):
    logger.info('registration request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['registration']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def registration_api():
    logger.info('registration API')
    return service_endpoint(request,
        oidcendpoint_app.endpoint_context.endpoint['registration_api'])


def authorization(request):
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['authorization']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def verify_user(request):
    """csrf is not needed because it uses oidc token in the post
    """
    token = request.POST.get('token')
    if not token:
        return HttpResponse('Access forbidden: invalid token.', status=403)

    authn_method = oidcendpoint_app.endpoint_context.\
                   authn_broker.get_method_by_id('user')

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
        authn_time=auth_args['iat'])

    endpoint = oidcendpoint_app.endpoint_context.endpoint['authorization']

    try:
        args = endpoint.authz_part2(user=user.username, request=authz_request,
                                    authn_event=authn_event)
    except ValueError as excp:
        msg = 'Something wrong with your Session ... {}'.format(excp)
        return HttpResponse(msg, status=403)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return HttpResponse(args.to_json(), status=400)

    response = do_response(endpoint, request, **args)
    return response


@csrf_exempt
def token(request):
    logger.info('token request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['token']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def userinfo(request):
    logger.info('userinfo request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['userinfo']
    # if not hasattr(request, 'debug'):
        # request.debug = 0
    # request.debug +=1
    return service_endpoint(request, _endpoint)


########
# LOGOUT
########
def session_endpoint(request):
    return service_endpoint(request,
        oidcendpoint_app.endpoint_context.endpoint['session'])


def check_session_iframe(request):
    if request.method == 'GET':
        req_args = request.GET
    elif request.method == 'POST':
        req_args = json.loads(request.POST)
    else:
        req_args = dict([(k, v) for k, v in request.body.items()])

    if req_args:
        # will contain client_id and origin
        if req_args['origin'] != current_app.endpoint_context.issuer:
            return 'error'
        if req_args['client_id'] != current_app.endpoint_context.cdb:
            return 'error'
        return 'OK'

    logger.debug('check_session_iframe: {}'.format(req_args))
    res = render(request, template_name='check_session_iframe.html')
    return res


@csrf_exempt
def rp_logout(request):
    _endp = oidcendpoint_app.endpoint_context.endpoint['session']
    _info = _endp.unpack_signed_jwt(request.POST['sjwt'])
    alla = None #request.POST.get('logout')

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
            _kakor = _endp.kill_cookies()
        except AttributeError as e:
            logger.debug('Cookie not implemented or not working.')
        #_add_cookie(res, _kakor)
    return res


def verify_logout(request):
    part = urlparse(oidcendpoint_app.endpoint_context.issuer)
    d = dict(op=part.hostname,
             do_logout='rp_logout',
             sjwt=request.GET['sjwt'] or request.POST['sjwt'])
    return render(request, 'logout.html', d)


def post_logout(request):
    return render(request, 'post_logout.html')
