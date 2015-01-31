"""Provide the base Message class and the argtypes decorator.

The base types are defined in RFC 4251 section 5.
"""

from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals


from collections import OrderedDict
import inspect
from itertools import chain as itc
from functools import wraps
from pyssh.base_types import Packable, Byte, String

from future.utils import with_metaclass

#pylint:disable=too-few-public-methods

class UnknownMessageError(Exception):
    """An unknown message"""
    def __init__(self, header):
        self.header = header
        msg = 'No match for header {}'.format(header)
        super(UnknownMessageError, self).__init__(msg, header)


def _ensure_type(name, value, restrictions):
    """A helper to ensure that value is in the types in restrictions[name]"""
    expected = restrictions[name]
    if not isinstance(value, expected):
        msg = '{} has invalid type {} (should be {})'
        msg = msg.format(name, type(value), expected)
        raise TypeError(msg)


def _create_init_wrapper(method, type_restrictions):
    """Create the __init__ wrapper. This wraps the class's __init__ in one that
    has type checking.
    """
    argspec = inspect.getargspec(method)
    @wraps(method)
    def init_wrapper(self, *args, **kwargs): # pylint: disable=C0111
        # preserve the actual kwargs.
        all_kwargs = dict(zip(argspec.args[1:], args))
        all_kwargs.update(kwargs)

        for argname, value in all_kwargs.items():
            _ensure_type(argname, value, type_restrictions)

        return method(self, *args, **kwargs)
    return init_wrapper

def _walk_spec_mro(cls):
    """Walk the class MRO in reverse order, yielding the SPEC attr as it is
    found on the class itself (and not inherited).
    """
    for scls in reversed(cls.__mro__):
        if 'SPEC' in vars(scls):
            yield scls.SPEC


class State(object):
    """Hold the state of an ssh transport session.

    auth method is set after auth method is chosen for context
    kex method is set after kex method is chosen for context
    request name is set after a global request for context
    in_kex is set if kex is in progress
    """
    def __init__(self, auth_method=None, kex_method=None, request_name=None, in_kex=False):
        self.auth_method = auth_method
        self.kex_method = kex_method
        self.request_name = request_name
        self.in_kex = in_kex

    def matches(self, satisfiers):
        """Check if the state matches the given satisfiers dictionary."""
        for key, value in satisfiers.items():
            try:
                if self.__dict__[key] != value:
                    return False
            except KeyError:
                msg = 'Invalid satisfiers! Expected one of {}, got {}'
                msg = msg.format(list(self.__dict__.keys()), key)
                raise RuntimeError(msg)
        return True



class MessageMeta(type):
    """Metaclass to wrap __init__ and create the various classmethods involving
    registration.
    """

    @classmethod
    def _set_init(mcs, bases, dct):
        """Override the __init__"""
        assert len(bases) == 1
        types = OrderedDict(itc.from_iterable(_walk_spec_mro(bases[0])))
        types.update(dct.get('SPEC', ()))
        try:
            old_init = dct['__init__']
        except KeyError:
            pass
        else:
            new_init = _create_init_wrapper(old_init, types)
            dct['__init__'] = new_init

    def _unpack_spec(cls, stream):
        """Unpack a class's SPEC from a stream."""
        for field_name, field_type in cls.SPEC:
            yield (field_name, field_type.unpack_from(stream))


    def unpack_from(cls, stream, state, kwargs):
        """Unpack the message subclass from a stream, given its state and the
        kwargs built up so far.
        """
        kwargs.update(cls._unpack_spec(stream))
        if not cls._key:
            return cls(**kwargs)
        lookup = kwargs.pop(cls._key, None) or String(getattr(state, cls._key))
        scls = cls.lookup(lookup)
        return scls.unpack_from(stream, state, kwargs)

    def _generic_register(cls, name, value):
        """A generic register technique that subclasses can use.
        In Message, the decorator it returns is the equvalent of::

            def decorator(scls):
                "Register the header with Message."
                cls._registered[header] = scls
                scls.HEADER = header
                return scls
        """
        registration = cls._registered
        assert value not in registration
        if not cls._key:
            cls._key = name.lower()

        def decorator(scls):
            """Register the value with this class."""
            registration[value] = scls
            setattr(scls, name, value)
            return scls

        return decorator

    def _generic_register_conditional(cls, name, value):
        """Decorator to register a Message conditionally.
        """
        registration = cls._registered
        if not cls._key:
            cls._key = name.lower()

        def decorator(scls):
            """Register the conditional header with Message."""
            assert hasattr(scls, 'SATISFIERS')
            try:
                conditional = registration[value]
            except KeyError:
                registration[value] = conditional = Conditional(name, value)
            conditional.append(scls)
            setattr(scls, name, value)
            return scls
        return decorator

    def lookup(cls, value):
        """Look up the registered value."""
        try:
            return cls._registered[value]
        except KeyError:
            raise UnknownMessageError(value)

    def __new__(mcs, name, bases, dct):
        # for some reason I have to do this in __new__
        mcs._set_init(bases, dct)
        return super(MessageMeta, mcs).__new__(mcs, name, bases, dct)

    def __init__(cls, name, bases, dct):
        cls._registered = {}
        cls._key = None
        super(MessageMeta, cls).__init__(name, bases, dct)


class Message(with_metaclass(MessageMeta, Packable)):
    """Base message class."""
    HEADER = None
    SPEC = [('header', Byte)]
    def __init__(self, header):
        self.header = header

    @classmethod
    def register(cls, header):
        """Decorator to register a class as the class for header.

        Use like:

            @Message.register(constants.SSH_MSG_FOO)
            class Foo(Message):
                ...
        """
        return cls._generic_register('HEADER', header)

    @classmethod
    def register_conditional(cls, header):
        """Decorator to register a Message conditionally."""
        return cls._generic_register_conditional('HEADER', header)

    def __eq__(self, other):
        if type(self) is not type(other):
            raise ValueError('different types')
        return all(getattr(self, attr, None) == getattr(other, attr, None)
                   for attr, _ in self.SPEC)


    def pack(self):
        specs = _walk_spec_mro(type(self))
        return b''.join(map(self._packspec, specs))

    def _packspec(self, spec):
        """Pack the entries in the class's SPEC.
        """
        attrs = (getattr(self, key) for key, _ in spec)
        return b''.join((a.pack() for a in attrs if a is not None))


class Conditional(list):
    """A conditional state that provides a similar interface to the regular
    Packable's unpack_from classmethod. It only stores classes.

    Instances of the word "MUST" in the following paragraph are meant in the
    RFC 2119 sense:

        Conditional Messages MUST implement a SATISFIERS classvalue that is a
        dictionary that contains all required key/value pairs to be satisfied by
        the current State (via state.matches(cls.SATISFIERS)). All SATISFIERS
        for a given header MUST be mutually exclusive.

    The second part is because I don't want to think about ordering, which is
    a hard problem.
    """
    def __init__(self, name, value):
        setattr(self, name, value)
        super(Conditional, self).__init__()

    def find_satisfying(self, state):
        """Find the entry that matches the state, or raise a KeyError."""
        for cls in self:
            if state.matches(cls.SATISFIERS):
                return cls
        raise KeyError(state)

    def unpack_from(self, stream, state, kwargs):
        """Unpack a satisfying class from the stream."""
        cls = self.find_satisfying(state)
        return cls.unpack_from(stream, state, kwargs)

