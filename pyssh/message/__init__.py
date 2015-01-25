"""This is the container for all SSH message handlers.

SSH messages have a one-byte header and a variable remainder.

Some SSH message types have a field that controls the contents of the remaining
field. These will be considered separate messages.
"""

from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from .base import Message, State

def unpack_from(stream, state):
    return Message.unpack_from(stream, state, {})
