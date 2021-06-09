import logging

from . application import oidcop_app

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
