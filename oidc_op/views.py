import logging
import json

from django.conf import settings
from django.http import (HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseRedirect,
                         JsonResponse)
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, render_to_response
from django.urls import reverse
from django.utils.translation import gettext as _
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.exception import FailedAuthentication
from oidcendpoint.oidc.token import AccessToken
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

from . application import oidcendpoint_application


logger = logging.getLogger(__name__)
# TODO: decide if refactor this with a decorator
oidcendpoint_app = oidcendpoint_application()


def _add_cookie(resp, cookie_spec):
    for key, _morsel in cookie_spec.items():
        kwargs = {'value': _morsel.value}
        for param in ['expires', 'path', 'comment', 'domain', 'max-age',
                      'secure',
                      'version']:
            if _morsel[param]:
                kwargs[param] = _morsel[param]
        resp.set_cookie(key, **kwargs)


def add_cookie(resp, cookie_spec):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)

    logger = oidcendpoint_app.srv_config.logger
    logger.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    logger.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            logger.info('Error Response: {}'.format(info['response']))
            resp = HttpResponse(info['response'], status=400)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            resp = HttpResponseRedirect(info['response'])
    else:
        if _response_placement == 'body':
            logger.info('Response: {}'.format(info['response']))
            resp = HttpResponse(info['response'], status=200)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            resp = HttpResponseRedirect(info['response'])

    for key, value in info['http_headers']:
        # set response headers
        resp[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


def service_endpoint(request, endpoint):
    """
    TODO: documentation here
    """
    logger = oidcendpoint_app.srv_config.logger
    logger.info('At the "{}" endpoint'.format(endpoint.endpoint_name))

    if hasattr(request, 'debug') and request.debug:
        import pdb; pdb.set_trace()

    try:
        # {'Content-Type': 'application/x-www-form-urlencoded', 'Connection': 'keep-alive', 'Content-Length': '493', 'Host': '127.0.0.1:8000', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Authorization': 'Basic SnFLS2M4RURYY1g2OmVlZDliYWZlMmZlZWRkNmQwMDYyOGVjMjViZGU0OTQ3MDBiNDdkNjVmMTc3ZTRmYWZkNGY5ZDUx', 'User-Agent': 'python-requests/2.22.0'}
        authn = request.headers['Authorization']
        pr_args = {'auth': authn}
    except KeyError:
        pr_args = {}

    if request.method == 'GET':
        try:
            # req_args should be
            # {'verify_ssl': True, 'jwe_header': None, 'jws_header': None, 'lax': False, 'jwt': None, '_dict': {'client_id': 'gTiwqgrDKgcH', 'state': 'F56tjqAeTGhqd7iyCFmlYmOiGunDoim6', 'response_type': ['code'], 'nonce': 'ypXILwdBHbRfWvZALk5vBkaP', 'redirect_uri': 'https://127.0.0.1:8090/authz_cb/flop', 'scope': ['openid', 'profile', 'email', 'address', 'phone']}}
            request.args = {k:v for k,v in request.GET.items()}
            req_args = endpoint.parse_request(request.args, **pr_args)
            if req_args._dict.get('error'):
                msg = 'Inconsistent req_args from endpoint.parse_request: {}'
                err = msg.format(req_args._dict.get('error_description'))
                # logger.error(err)
                raise Exception(err)

        except Exception as err:
            logger.error(err)
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': str(err),
                'method': request.method
                }, status=400)
    else:
        if request.body and not request.POST:
            req_args = request.body \
                       if isinstance(request.body, str) else \
                       request.body.decode()
        else:
            req_args = {k:v for k,v in request.POST.items()}
        try:
            req_args = endpoint.parse_request(req_args, **pr_args)
        except Exception as err:
            logger.error(err)
            return JsonResponse(json.dumps({
                'error': 'invalid_request',
                'error_description': str(err),
                'method': request.method
                }), status=400)

    logger.info('request: {}'.format(req_args))
    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        # <oidcmsg.oauth2.ResponseMessage object at 0x7f654122cac8>
        # {'lax': False, 'verify_ssl': True, 'jwe_header': None, '_dict': {'error': 'invalid_request', 'error_description': "Missing required attribute 'rel'"}, 'jwt': None, 'jws_header': None}
        return JsonResponse(req_args.__dict__, status=400)

    if request.COOKIES:
        logger.debug(request.COOKIES)
        # TODO: cookie
        kwargs = {'cookie': request.COOKIES}
    else:
        kwargs = {}

    try:
        if isinstance(endpoint, AccessToken):
            args = endpoint.process_request(AccessTokenRequest(**req_args),
                                            **kwargs)
        else:
            args = endpoint.process_request(req_args, **kwargs)
    except Exception as err:
        message = '{}'.format(err)
        logger.error(message)
        return JsonResponse(json.dumps({
            'error': 'invalid_request',
            'error_description': str(err)
            }), status=400)

    logger.info('Response args: {}'.format(args))

    if 'redirect_location' in args:
        return HttpResponseRedirect(args['redirect_location'])
    if 'http_response' in args:
        return HttpResponse(args['http_response'], status=200)

    return do_response(endpoint, req_args, **args)


def well_known(request, service):
    """
    /.well-known/<service>

    oidcendpoint_app is rohe's flask_op current_app
    """
    if service == 'openid-configuration':
        _endpoint = oidcendpoint_app.endpoint_context.endpoint['provider_info']
    # if service == 'openid-federation':
    #     _endpoint = current_app.endpoint_context.endpoint['provider_info']
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

    # TODO: 'salt' should change/be randomized/be configured
    authn_event = create_authn_event(
        uid=user.username, salt='salt',
        authn_info=auth_args['authn_class_ref'],
        authn_time=auth_args['iat'])

    endpoint = oidcendpoint_app.endpoint_context.endpoint['authorization']
    args = endpoint.authz_part2(user=user.username, request=authz_request,
                                authn_event=authn_event)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return HttpResponse(args.to_json(), status=400)

    response = do_response(endpoint, request, **args)
    return response


@csrf_exempt
def token(request):
    logger.info('token request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['token']

    # if not hasattr(request, 'debug'):
        # request.debug = 0
    # request.debug +=1
    return service_endpoint(request, _endpoint)


@csrf_exempt
def userinfo(request):
    logger.info('userinfo request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['userinfo']
    # if not hasattr(request, 'debug'):
        # request.debug = 0
    # request.debug +=1
    return service_endpoint(request, _endpoint)
