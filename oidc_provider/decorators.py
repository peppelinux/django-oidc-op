import json
import logging

from django.http import JsonResponse
from oidcop.exception import InvalidClient

from . application import oidcop_app
from . models import get_client_by_id

logger = logging.getLogger(__name__)


def debug_request(endpoint_name, request):
    _post = (f'POST:{request.POST}' if request.POST
             else f'BODY:{request.body.decode()}' if request.body
             else '')

    bearer = request.META.get('HTTP_AUTHORIZATION')
    _authz_header = f'- Authorization Header: {bearer}' if bearer else ''

    logger.debug(
        f'{endpoint_name} request GET: {request.GET} - {_post}{_authz_header}'
    )


def _fill_cdb(request) -> None:
    client_id = request.GET.get('client_id') or request.POST.get('client_id')
    _msg = f'Client {client_id} not found!'
    if client_id:
        client = get_client_by_id(client_id)
        if client:
            ec = oidcop_app.endpoint_context
            ec.endpoint_context.cdb = {
                client_id: client.serialize()
            }
            return
    else:
        logger.warning(_msg)
        raise InvalidClient(_msg)


def prepare_oidc_endpoint(func_to_decorate):
    """ store_params_in_session as a funcion decorator
    """
    def new_func(*original_args, **original_kwargs):
        request = original_args[0]
        _name = func_to_decorate.__name__
        debug_request(f'{_name}', request)

        ec = oidcop_app.endpoint_context
        # yes, in flush we believe ...
        ec.endpoint_context.session_manager.flush()

        return func_to_decorate(*original_args, **original_kwargs)

    return new_func


def fill_cdb_by_request(func_to_decorate):
    """ store_params_in_session as a funcion decorator
    """
    def new_func(*original_args, **original_kwargs):
        request = original_args[0]

        try:
            _fill_cdb(request)
            return func_to_decorate(*original_args, **original_kwargs)
        except InvalidClient as e:
            return JsonResponse(json.dumps({
                'error': 'invalid_request',
                'error_description': str(e),
                'method': request.method
            }), safe=False, status=403)
    return new_func
