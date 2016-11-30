import functools

from oslo_log import log as logging
import testtools

from tempest import config
from tempest.lib import decorators

LOG = logging.getLogger(__name__)

CONF = config.CONF

idempotent_id = decorators.idempotent_id


def attr(**kwargs):
    """A decorator which applies the testtools attr decorator

    This decorator applies the testtools.testcase.attr if it is in the list of
    attributes to testtools we want to apply.
    """

    def decorator(f):
        if 'type' in kwargs and isinstance(kwargs['type'], str):
            f = testtools.testcase.attr(kwargs['type'])(f)
        elif 'type' in kwargs and isinstance(kwargs['type'], list):
            for attr in kwargs['type']:
                f = testtools.testcase.attr(attr)(f)
        return f

    return decorator


def requires_ext(**kwargs):
    """A decorator to skip tests if an extension is not enabled

    @param extension
    @param service
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*func_args, **func_kwargs):
            if not is_extension_enabled(kwargs['extension'],
                                        kwargs['service']):
                msg = "Skipped because %s extension: %s is not enabled" % (
                    kwargs['service'], kwargs['extension'])
                raise testtools.TestCase.skipException(msg)
            return func(*func_args, **func_kwargs)
        return wrapper
    return decorator


def is_extension_enabled(extension_name, service):
    """A function that will check the list of enabled extensions from config

    """
    config_dict = {
        'compute': CONF.compute_feature_enabled.api_extensions,
        'volume': CONF.volume_feature_enabled.api_extensions,
        'network': CONF.network_feature_enabled.api_extensions,
        'object': CONF.object_storage_feature_enabled.discoverable_apis,
        'identity': CONF.identity_feature_enabled.api_extensions
    }
    if len(config_dict[service]) == 0:
        return False
    if config_dict[service][0] == 'all':
        return True
    if extension_name in config_dict[service]:
        return True
    return False
