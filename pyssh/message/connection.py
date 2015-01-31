"""All the messages with a header between 80-127.

Mostly from RFC 4254: Connection protocol
"""
from pyssh.base_types import Byte, String, Boolean, UInt32
from pyssh.constants import (
    SSH_MSG_GLOBAL_REQUEST, SSH_MSG_REQUEST_SUCCESS, SSH_MSG_REQUEST_FAILURE,
    SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_CLOSE,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE,
    SSH_MSG_CHANNEL_WINDOW_ADJUST, SSH_MSG_CHANNEL_DATA,
    SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_CLOSE,
    SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE,
    CHANNEL_TYPE_SESSION, GLOBAL_REQUEST_TCPIP_FORWARD,
    GLOBAL_REQUEST_TCPIP_FORWARD_REPLY, GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
    CHANNEL_REQUEST_TYPE_PTY, CHANNEL_REQUEST_TYPE_ENV,
    CHANNEL_REQUEST_TYPE_SHELL, CHANNEL_REQUEST_TYPE_EXEC,
    CHANNEL_REQUEST_TYPE_SUBSYSTEM, CHANNEL_REQUEST_TYPE_WINDOW_CHANGE,
    CHANNEL_REQUEST_TYPE_XON_XOFF, CHANNEL_REQUEST_TYPE_SIGNAL,
    CHANNEL_REQUEST_TYPE_EXIT_STATUS, CHANNEL_REQUEST_TYPE_EXIT_SIGNAL
    )

from .base import Message

# pylint:disable=R0903,R0913

# Global requests are messy. Some requests have a special success value,
# but many don't. All you can do is keep state at the transport level and
# handle it during message lookup.
@Message.register(Byte(SSH_MSG_GLOBAL_REQUEST))
class GlobalRequest(Message):
    """Global Requests: Section 4"""
    REQUEST_NAME = None
    SPEC = [('request_name', String), ('want_reply', Boolean)]
    def __init__(self, request_name, want_reply):
        super(GlobalRequest, self).__init__(self.HEADER)
        self.request_name = request_name
        self.want_reply = want_reply

    @classmethod
    def register(cls, request_name):
        return cls._generic_register('REQUEST_NAME', request_name)

    def setstate(self, state):
        """Set the global state after this request."""
        assert not state.request_name
        state.request_name = self.request_name.value


@Message.register(Byte(SSH_MSG_REQUEST_SUCCESS))
class RequestSuccess(Message):
    """Global Requests: Section 4"""
    SPEC = []
    def __init__(self):
        super(RequestSuccess, self).__init__(self.HEADER)

    @classmethod
    def register(cls, request_name):
        return cls._generic_register('REQUEST_NAME', request_name)


@Message.register(Byte(SSH_MSG_REQUEST_FAILURE))
class RequestFailure(Message):
    """Global Requests: Section 4"""
    SPEC = []
    def __init__(self):
        super(RequestFailure, self).__init__(self.HEADER)



# Channels
@Message.register(Byte(SSH_MSG_CHANNEL_OPEN))
class ChannelOpen(Message):
    """Channel Open: Section 5.1"""
    CHANNEL_TYPE = None
    _REGISTRATION = {}
    SPEC = [('channel_type', String), ('sender_channel', UInt32),
            ('initial_window', UInt32), ('max_packet', UInt32)]
    def __init__(self, channel_type, sender_channel, initial_window,
                 max_packet):
        super(ChannelOpen, self).__init__(self.HEADER)
        self.channel_type = channel_type
        self.sender_channel = sender_channel
        self.initial_window = initial_window
        self.max_packet = max_packet

    @classmethod
    def register(cls, channel_type):
        return cls._generic_register('CHANNEL_TYPE', channel_type)



@Message.register(Byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION))
class ChannelOpenConfirmation(Message):
    """Channel Open: Section 5.1"""
    SPEC = [('recipient_channel', UInt32), ('sender_channel', UInt32),
            ('initial_window', UInt32), ('max_packet', UInt32)]
    def __init__(self, recipient_channel, sender_channel, initial_window,
                 max_packet):
        super(ChannelOpenConfirmation, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.sender_channel = sender_channel
        self.initial_window = initial_window
        self.max_packet = max_packet


@Message.register(Byte(SSH_MSG_CHANNEL_OPEN_FAILURE))
class ChannelOpenFailure(Message):
    """Channel Open: Section 5.1"""
    SPEC = [('recipient_channel', UInt32), ('reason_code', UInt32),
            ('description', String), ('language_tag', String)]
    def __init__(self, recipient_channel, reason_code, description,
                 language_tag):
        super(ChannelOpenFailure, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.reason_code = reason_code
        self.description = description
        self.language_tag = language_tag


@Message.register(Byte(SSH_MSG_CHANNEL_WINDOW_ADJUST))
class ChannelWindowAdjust(Message):
    """Channel Window Adjust: Section 5.2"""
    SPEC = [('recipient_channel', UInt32), ('bytes_to_add', UInt32)]
    def __init__(self, recipient_channel, bytes_to_add):
        super(ChannelWindowAdjust, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.bytes_to_add = bytes_to_add



@Message.register(Byte(SSH_MSG_CHANNEL_DATA))
class ChannelData(Message):
    """Channel Data: Section 5.2"""
    SPEC = [('recipient_channel', UInt32), ('data', String)]
    def __init__(self, recipient_channel, data):
        super(ChannelData, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.data = data


@Message.register(Byte(SSH_MSG_CHANNEL_EXTENDED_DATA))
class ChannelExtendedData(Message):
    """Channel Extended Data: Section 5.2"""
    SPEC = [('recipient_channel', UInt32), ('data_type_code', UInt32),
            ('data', String)]
    def __init__(self, recipient_channel, data_type_code, data):
        super(ChannelExtendedData, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.data_type_code = data_type_code
        self.data = data


@Message.register(Byte(SSH_MSG_CHANNEL_EOF))
class ChannelEOF(Message):
    """Channel EOF: Section 5.3"""
    SPEC = [('recipient_channel', UInt32)]
    def __init__(self, recipient_channel):
        super(ChannelEOF, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel


@Message.register(Byte(SSH_MSG_CHANNEL_CLOSE))
class ChannelClose(Message):
    """Channel Close: Section 5.3"""
    SPEC = [('recipient_channel', UInt32)]
    def __init__(self, recipient_channel):
        super(ChannelClose, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel



@Message.register(Byte(SSH_MSG_CHANNEL_REQUEST))
class ChannelRequest(Message):
    """Channel Request: Section 5.4"""
    SPEC = [('recipient_channel', UInt32), ('request_type', String),
            ('want_reply', Boolean)]
    def __init__(self, recipient_channel, request_type, want_reply):
        super(ChannelRequest, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel
        self.request_type = request_type
        self.want_reply = want_reply

    @classmethod
    def register(cls, request_type):
        return cls._generic_register('REQUEST_TYPE', request_type)


@Message.register(Byte(SSH_MSG_CHANNEL_SUCCESS))
class ChannelSuccess(Message):
    """Channel Success: Section 5.4"""
    SPEC = [('recipient_channel', UInt32)]
    def __init__(self, recipient_channel):
        super(ChannelSuccess, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel


@Message.register(Byte(SSH_MSG_CHANNEL_FAILURE))
class ChannelFailure(Message):
    """Channel Failure: Section 5.4"""
    SPEC = [('recipient_channel', UInt32)]
    def __init__(self, recipient_channel):
        super(ChannelFailure, self).__init__(self.HEADER)
        self.recipient_channel = recipient_channel



# Sessions, section 6
@ChannelOpen.register(String(CHANNEL_TYPE_SESSION))
class SessionOpen(ChannelOpen):
    """Session Open: Section 6"""
    SPEC = []
    def __init__(self, sender_channel, initial_window, max_packet):
        super(SessionOpen, self).__init__(self.CHANNEL_TYPE, sender_channel,
                                          initial_window, max_packet)


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_PTY))
class PTYRequest(ChannelRequest):
    """PTY Request: Section 6.2"""
    SPEC = [('term', String), ('width_ch', UInt32), ('rows_ch', UInt32),
            ('width_px', UInt32), ('height_px', UInt32), ('modes', String)]
    def __init__(self, recipient_channel, want_reply, term, width_ch, rows_ch,
                 width_px, height_px, modes):
        super(PTYRequest, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                         want_reply)
        self.term = term
        self.width_ch = width_ch
        self.rows_ch = rows_ch
        self.width_px = width_px
        self.height_px = height_px
        self.modes = modes

# TODO: X11 forwarding/X11 channels (section 6.3)


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_ENV))
class EnvRequest(ChannelRequest):
    """Env Request: Section 6.4"""
    SPEC = [('variable_name', String), ('variable_value', String)]
    def __init__(self, recipient_channel, want_reply, variable_name,
                 variable_value):
        super(EnvRequest, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                         want_reply)
        self.variable_name = variable_name
        self.variable_value = variable_value


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_SHELL))
class ShellRequest(ChannelRequest):
    """Shell request: Section 6.5"""
    SPEC = []
    def __init__(self, recipient_channel, want_reply):
        super(ShellRequest, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                           want_reply)

@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_EXEC))
class ExecRequest(ChannelRequest):
    """Exec Request: Section 6.5"""
    SPEC = [('command', String)]
    def __init__(self, recipient_channel, want_reply, command):
        super(ExecRequest, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                          want_reply)
        self.command = command


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_SUBSYSTEM))
class SubsystemRequest(ChannelRequest):
    """Subsystem Request: Section 6.5"""
    SPEC = [('subsystem_name', String)]
    def __init__(self, recipient_channel, want_reply, subsystem_name):
        super(SubsystemRequest, self).__init__(recipient_channel,
                                               self.REQUEST_TYPE, want_reply)
        self.subsystem_name = subsystem_name


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_WINDOW_CHANGE))
class WindowChangeRequest(ChannelRequest):
    """Window Change Request: Section 6.7"""
    SPEC = [('term', String), ('width_ch', UInt32), ('rows_ch', UInt32),
            ('width_px', UInt32), ('height_px', UInt32), ('modes', String)]
    def __init__(self, recipient_channel, want_reply, term, width_ch, rows_ch,
                 width_px, height_px, modes):
        super(WindowChangeRequest, self).__init__(recipient_channel,
                                                  self.REQUEST_TYPE,
                                                  want_reply)
        self.term = term
        self.width_ch = width_ch
        self.rows_ch = rows_ch
        self.width_px = width_px
        self.height_px = height_px
        self.modes = modes


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_XON_XOFF))
class LocalFlowControl(ChannelRequest):
    """Local Flow Control: Section 6.8"""
    SPEC = [('client_can_do', Boolean)]
    def __init__(self, recipient_channel, client_can_do, want_reply=None):
        super(LocalFlowControl, self).__init__(recipient_channel,
                                               self.REQUEST_TYPE,
                                               Boolean(False))
        self.client_can_do = client_can_do


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_SIGNAL))
class SignalRequest(ChannelRequest):
    """Signal Request: Section 6.9"""
    SPEC = [('signal_name', String)]
    def __init__(self, recipient_channel, signal_name, want_reply=None):
        super(SignalRequest, self).__init__(recipient_channel,
                                            self.REQUEST_TYPE, Boolean(False))
        self.signal_name = signal_name


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_EXIT_STATUS))
class ExitStatus(ChannelRequest):
    """Returning Exit Status: Section 6.10"""
    SPEC = [('exit_status', UInt32)]
    def __init__(self, recipient_channel, exit_status, want_reply=None):
        super(ExitStatus, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                         Boolean(False))
        self.exit_status = exit_status


@ChannelRequest.register(String(CHANNEL_REQUEST_TYPE_EXIT_SIGNAL))
class ExitSignal(ChannelRequest):
    """Returning Exit Signal: Section 6.10"""
    SPEC = [('signal_name', String), ('core_dumped', Boolean),
            ('err_msg', String), ('language_tag', String)]
    def __init__(self, recipient_channel, signal_name, core_dumped, err_msg,
                 language_tag, want_reply=None):
        super(ExitSignal, self).__init__(recipient_channel, self.REQUEST_TYPE,
                                         Boolean(False))
        self.signal_name = signal_name
        self.core_dumped = core_dumped
        self.err_msg = err_msg
        self.language_tag = language_tag


@GlobalRequest.register(String(GLOBAL_REQUEST_TCPIP_FORWARD))
class TCPIPForwardRequest(GlobalRequest):
    """TCPIP Forwarding: Section 7.1"""
    SPEC = [('address', String), ('port', UInt32)]
    def __init__(self, want_reply, address, port):
        self.address = address
        self.port = port
        super(TCPIPForwardRequest, self).__init__(self.REQUEST_NAME, want_reply)

    def setstate(self, state):
        """Set the state after calling."""
        if self.want_reply.value:
            state.request_name = GLOBAL_REQUEST_TCPIP_FORWARD_REPLY
        else:
            state.request_name = GLOBAL_REQUEST_TCPIP_FORWARD


@GlobalRequest.register(String(GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD))
class TCPIPForwardCancel(GlobalRequest):
    """TCPIP Forwarding: Section 7.1"""
    SPEC = [('address', String), ('port', UInt32)]
    def __init__(self, want_reply, address, port):
        self.address = address
        self.port = port
        super(TCPIPForwardCancel, self).__init__(self.REQUEST_NAME, want_reply)



@RequestSuccess.register(String(GLOBAL_REQUEST_TCPIP_FORWARD))
class TCPIPForwardSuccess(RequestSuccess):
    """TCPIP Forwarding: Section 7.1"""
    SPEC = []

@RequestSuccess.register(String(GLOBAL_REQUEST_TCPIP_FORWARD_REPLY))
class TCPIPForwardSuccessAssigned(RequestSuccess):
    """TCPIP Forwarding: Section 7.1"""
    SPEC = [('port', UInt32)]
    def __init__(self, port):
        super(TCPIPForwardSuccessAssigned, self).__init__()
        self.port = port

