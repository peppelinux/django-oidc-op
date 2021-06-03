import logging

from . application import oidcop_app

logger = logging.getLogger(__name__)


def debug_request(endpoint_name, request):
    logger.debug(
        f'{endpoint_name} request GET: {request.GET} - POST:{request.POST}'
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
