"""Tests for Connection messages.
"""

from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals


from pyssh.message import connection
from pyssh.base_types import Byte, String, Boolean, UInt32
from pyssh.message import unpack_from, State
from pyssh.constants import (SSH_MSG_GLOBAL_REQUEST, SSH_MSG_REQUEST_SUCCESS,
                             SSH_MSG_REQUEST_FAILURE,
                             SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_CLOSE,
                             SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                             SSH_MSG_CHANNEL_OPEN_FAILURE,
                             SSH_MSG_CHANNEL_WINDOW_ADJUST,
                             SSH_MSG_CHANNEL_DATA,
                             SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_EOF,
                             SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_REQUEST,
                             SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE,
                             CHANNEL_TYPE_SESSION,
                             GLOBAL_REQUEST_TCPIP_FORWARD,
                             GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
                             GLOBAL_REQUEST_TCPIP_FORWARD_REPLY,
                             CHANNEL_REQUEST_TYPE_PTY, CHANNEL_REQUEST_TYPE_ENV,
                             CHANNEL_REQUEST_TYPE_SHELL,
                             CHANNEL_REQUEST_TYPE_EXEC,
                             CHANNEL_REQUEST_TYPE_SUBSYSTEM,
                             CHANNEL_REQUEST_TYPE_WINDOW_CHANGE,
                             CHANNEL_REQUEST_TYPE_XON_XOFF,
                             CHANNEL_REQUEST_TYPE_SIGNAL,
                             CHANNEL_REQUEST_TYPE_EXIT_STATUS,
                             CHANNEL_REQUEST_TYPE_EXIT_SIGNAL
                             )

import pytest

import os
import unittest
from io import BytesIO


class BaseConnection(object):
    def test_init(self):
        inst = self.cls(*self.args)
        assert inst.HEADER == self.header
        return inst

    def test_pack(self):
        inst = self.cls(*self.args)
        assert inst.pack() == self.packed
        return inst

    def test_unpack(self):
        stream = BytesIO(self.packed)
        inst = unpack_from(stream, state=self.state)
        assert isinstance(inst, self.cls)
        assert not stream.read()
        return inst

class TestGlobalRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_GLOBAL_REQUEST)
        self.request_name = String(b'some-request')
        self.want_reply = Boolean(True)

        self.args = (self.request_name, self.want_reply)
        self.cls = connection.GlobalRequest
        self.packed = (
            b'\x50'
            b'\x00\x00\x00\x0Csome-request'
            b'\x01'
        )
        self.state = State()

    def tearDown(self):
        self.cls._registered.pop(self.request_name, None)

    def test_unpack(self):
        @self.cls.register(self.request_name)
        class DemoRequest(self.cls):
            SPEC = []
            def __init__(self, want_reply):
                super(DemoRequest, self).__init__(self.REQUEST_NAME, want_reply)

        inst = unpack_from(BytesIO(self.packed), self.state)
        assert isinstance(inst, DemoRequest)

    def test_setstate(self):
        inst = self.cls(*self.args)
        inst.setstate(self.state)
        assert self.state.request_name == b'some-request'



class TestRequestSuccess(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_REQUEST_SUCCESS)
        self.request_name = String(b'some-request')

        self.args = ()
        self.cls = connection.RequestSuccess
        self.packed = b'\x51'
        self.state = State(request_name=self.request_name.value)

    def tearDown(self):
        self.cls._registered.pop(self.request_name, None)

    def test_unpack(self):
        @self.cls.register(self.request_name)
        class DemoRequestSuccess(self.cls):
            pass

        inst = unpack_from(BytesIO(self.packed), self.state)
        assert isinstance(inst, DemoRequestSuccess)


class TestRequestfailure(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_REQUEST_FAILURE)
        self.request_name = String(b'some-request')

        self.args = ()
        self.cls = connection.RequestFailure
        self.packed = b'\x52'
        self.state = State(request_name=self.request_name.value)


class TestChannelOpen(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_OPEN)
        self.channel_type = String(b'some-channel')
        self.sender_channel = UInt32(0)
        self.initial_window = UInt32(1024)
        self.max_packet = UInt32(256)

        self.args = (self.channel_type, self.sender_channel,
                     self.initial_window, self.max_packet)
        self.cls = connection.ChannelOpen
        self.packed = (
            b'\x5A'
            b'\x00\x00\x00\x0Csome-channel'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x04\x00'
            b'\x00\x00\x01\x00'
        )
        self.state = State()

    def tearDown(self):
        self.cls._registered.pop(self.channel_type, None)

    def test_unpack(self):
        @self.cls.register(self.channel_type)
        class DemoChannelOpen(self.cls):
            SPEC = []
            def __init__(self, sender_channel, initial_window, max_packet):
                super(DemoChannelOpen, self).__init__(self.CHANNEL_TYPE,
                                                      sender_channel,
                                                      initial_window,
                                                      max_packet)

        inst = unpack_from(BytesIO(self.packed), self.state)
        assert isinstance(inst, DemoChannelOpen)


class TestChannelOpenConfirmation(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        self.recipient_channel = UInt32(1)
        self.sender_channel = UInt32(0)
        self.initial_window = UInt32(1024)
        self.max_packet = UInt32(256)

        self.args = (self.recipient_channel, self.sender_channel,
                     self.initial_window, self.max_packet)
        self.cls = connection.ChannelOpenConfirmation
        self.packed = (
            b'\x5B'
            b'\x00\x00\x00\x01'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x04\x00'
            b'\x00\x00\x01\x00'
        )
        self.state = State()

class TestChannelOpenFailure(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_OPEN_FAILURE)
        self.recipient_channel = UInt32(0)
        self.reason_code = UInt32(0xFFFFFFFF)
        self.description = String(b'some-description')
        self.language_tag = String(b'en-us')

        self.args = (self.recipient_channel, self.reason_code,
                     self.description, self.language_tag)
        self.cls = connection.ChannelOpenFailure
        self.packed = (
            b'\x5C'
            b'\x00\x00\x00\x00'
            b'\xFF\xFF\xFF\xFF'
            b'\x00\x00\x00\x10some-description'
            b'\x00\x00\x00\x05en-us'
        )
        self.state = State()


class TestChannelWindowAdjust(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_WINDOW_ADJUST)
        self.recipient_channel = UInt32(0)
        self.bytes_to_add = UInt32(256)

        self.args = (self.recipient_channel, self.bytes_to_add)
        self.cls = connection.ChannelWindowAdjust
        self.packed = (
            b'\x5D'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x01\x00'
        )
        self.state = State()


class TestChannelData(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_DATA)
        self.recipient_channel = UInt32(0)
        self.data = String(b'some-data')

        self.args = (self.recipient_channel, self.data)
        self.cls = connection.ChannelData
        self.packed = (
            b'\x5E'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x09some-data'
        )
        self.state = State()


class TestChannelExtendedData(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_EXTENDED_DATA)
        self.recipient_channel = UInt32(0)
        self.data_type_code = UInt32(0xFFFFFFFF)
        self.data = String(b'some-data')

        self.args = (self.recipient_channel, self.data_type_code, self.data)
        self.cls = connection.ChannelExtendedData
        self.packed = (
            b'\x5F'
            b'\x00\x00\x00\x00'
            b'\xFF\xFF\xFF\xFF'
            b'\x00\x00\x00\x09some-data'
        )
        self.state = State()



class TestChannelEOF(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_EOF)
        self.recipient_channel = UInt32(0)

        self.args = (self.recipient_channel,)
        self.cls = connection.ChannelEOF
        self.packed = (
            b'\x60'
            b'\x00\x00\x00\x00'
        )
        self.state = State()


class TestChannelClose(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_CLOSE)
        self.recipient_channel = UInt32(0)

        self.args = (self.recipient_channel,)
        self.cls = connection.ChannelClose
        self.packed = (
            b'\x61'
            b'\x00\x00\x00\x00'
        )
        self.state = State()



class TestChannelRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0)
        self.request_type = String(b'some-request')
        self.want_reply = Boolean(False)

        self.args = (self.recipient_channel, self.request_type, self.want_reply)
        self.cls = connection.ChannelRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x0Csome-request'
            b'\x00'
        )
        self.state = State()

    def test_unpack(self):
        @self.cls.register(self.request_type)
        class DemoChannelRequest(self.cls):
            SPEC = []
            def __init__(self, recipient_channel, want_reply):
                super(DemoChannelRequest, self).__init__(recipient_channel,
                                                         self.REQUEST_TYPE,
                                                         want_reply)

        inst = unpack_from(BytesIO(self.packed), self.state)
        assert isinstance(inst, DemoChannelRequest)


class TestChannelSuccess(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_SUCCESS)
        self.recipient_channel = UInt32(0)

        self.args = (self.recipient_channel,)
        self.cls = connection.ChannelSuccess
        self.packed = (
            b'\x63'
            b'\x00\x00\x00\x00'
        )
        self.state = State()


class TestChannelFailure(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_FAILURE)
        self.recipient_channel = UInt32(0)

        self.args = (self.recipient_channel,)
        self.cls = connection.ChannelFailure
        self.packed = (
            b'\x64'
            b'\x00\x00\x00\x00'
        )
        self.state = State()


class TestSessionOpen(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_OPEN)
        self.channel_type = String(CHANNEL_TYPE_SESSION)
        self.sender_channel = UInt32(1)
        self.initial_window = UInt32(1024)
        self.max_packet = UInt32(256)

        self.args = (self.sender_channel, self.initial_window, self.max_packet)
        self.cls = connection.SessionOpen
        self.packed = (
            b'\x5A'
            b'\x00\x00\x00\x07session'
            b'\x00\x00\x00\x01'
            b'\x00\x00\x04\x00'
            b'\x00\x00\x01\x00'
        )
        self.state = State()


class TestPTYRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(1)
        self.request_type = String(CHANNEL_REQUEST_TYPE_PTY)
        self.want_reply = Boolean(False)
        self.term = String(b'some-term')
        self.width_ch = UInt32(80)
        self.rows_ch = UInt32(24)
        self.width_px = UInt32(0)
        self.height_px = UInt32(0)
        self.modes = String(b'\x00')

        self.args = (self.recipient_channel, self.want_reply, self.term,
                     self.width_ch, self.rows_ch, self.width_px, self.height_px,
                     self.modes)
        self.cls = connection.PTYRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\x00\x01'
            b'\x00\x00\x00\x07pty-req'
            b'\x00'
            b'\x00\x00\x00\x09some-term'
            b'\x00\x00\x00\x50'
            b'\x00\x00\x00\x18'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x01\x00'
        )
        self.state = State()


class TestEnvRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(1)
        self.request_type = String(CHANNEL_REQUEST_TYPE_ENV)
        self.want_reply = Boolean(False)
        self.variable_name = String(b'foo')
        self.variable_value = String(b'bar')

        self.args = (self.recipient_channel, self.want_reply,
                     self.variable_name, self.variable_value)
        self.cls = connection.EnvRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\x00\x01'
            b'\x00\x00\x00\x03env'
            b'\x00'
            b'\x00\x00\x00\x03foo'
            b'\x00\x00\x00\x03bar'
        )
        self.state = State()


class TestShellRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFFFF)
        self.request_type = String(CHANNEL_REQUEST_TYPE_ENV)
        self.want_reply = Boolean(True)

        self.args = (self.recipient_channel, self.want_reply)
        self.cls = connection.ShellRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\xFF\xFF'
            b'\x00\x00\x00\x05shell'
            b'\x01'
        )
        self.state = State()


class TestExecRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFFFE)
        self.request_type = String(CHANNEL_REQUEST_TYPE_EXEC)
        self.want_reply = Boolean(False)
        self.command = String(b'do-stuff')

        self.args = (self.recipient_channel, self.want_reply, self.command)
        self.cls = connection.ExecRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\xFF\xFE'
            b'\x00\x00\x00\x04exec'
            b'\x00'
            b'\x00\x00\x00\x08do-stuff'
        )
        self.state = State()



class TestSubsystemRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFFFE)
        self.request_type = String(CHANNEL_REQUEST_TYPE_SUBSYSTEM)
        self.want_reply = Boolean(False)
        self.command = String(b'some-subsystem')

        self.args = (self.recipient_channel, self.want_reply, self.command)
        self.cls = connection.SubsystemRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\xFF\xFE'
            b'\x00\x00\x00\x09subsystem'
            b'\x00'
            b'\x00\x00\x00\x0Esome-subsystem'
        )
        self.state = State()




class TestWindowChangeRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(1)
        self.request_type = String(CHANNEL_REQUEST_TYPE_WINDOW_CHANGE)
        self.want_reply = Boolean(False)
        self.term = String(b'some-term')
        self.width_ch = UInt32(80)
        self.rows_ch = UInt32(24)
        self.width_px = UInt32(0)
        self.height_px = UInt32(0)
        self.modes = String(b'\x00')

        self.args = (self.recipient_channel, self.want_reply, self.term,
                     self.width_ch, self.rows_ch, self.width_px, self.height_px,
                     self.modes)
        self.cls = connection.WindowChangeRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\x00\x01'
            b'\x00\x00\x00\x0Dwindow-change'
            b'\x00'
            b'\x00\x00\x00\x09some-term'
            b'\x00\x00\x00\x50'
            b'\x00\x00\x00\x18'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x01\x00'
        )
        self.state = State()


class TestLocalFlowControl(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFEFF)
        self.request_type = String(CHANNEL_REQUEST_TYPE_XON_XOFF)
        self.client_can_do = Boolean(False)

        self.args = (self.recipient_channel, self.client_can_do)
        self.cls = connection.LocalFlowControl
        self.packed = (
            b'\x62'
            b'\x00\x00\xFE\xFF'
            b'\x00\x00\x00\x08xon-xoff'
            b'\x00'
            b'\x00'
        )
        self.state = State()


class TestSignalRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFEFF)
        self.request_type = String(CHANNEL_REQUEST_TYPE_SIGNAL)
        self.signal_name = String(b'NONE@test')

        self.args = (self.recipient_channel, self.signal_name)
        self.cls = connection.SignalRequest
        self.packed = (
            b'\x62'
            b'\x00\x00\xFE\xFF'
            b'\x00\x00\x00\x06signal'
            b'\x00'
            b'\x00\x00\x00\x09NONE@test'
        )
        self.state = State()




class TestExitStatus(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFEFF)
        self.request_type = String(CHANNEL_REQUEST_TYPE_EXIT_STATUS)
        self.exit_status = UInt32(0xFFFFFFFF)

        self.args = (self.recipient_channel, self.exit_status)
        self.cls = connection.ExitStatus
        self.packed = (
            b'\x62'
            b'\x00\x00\xFE\xFF'
            b'\x00\x00\x00\x0Bexit-status'
            b'\x00'
            b'\xFF\xFF\xFF\xFF'
        )
        self.state = State()


class TestExitSignal(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_CHANNEL_REQUEST)
        self.recipient_channel = UInt32(0xFFEF)
        self.request_type = String(CHANNEL_REQUEST_TYPE_EXIT_SIGNAL)
        self.signal_name = String(b'NONE@test')
        self.core_dumped = Boolean(False)
        self.err_msg = String(b'no-msg')
        self.language_tag = String(b'en-us')

        self.args = (self.recipient_channel, self.signal_name, self.core_dumped,
                     self.err_msg, self.language_tag)
        self.cls = connection.ExitSignal
        self.packed = (
            b'\x62'
            b'\x00\x00\xFF\xEF'
            b'\x00\x00\x00\x0Bexit-signal'
            b'\x00'
            b'\x00\x00\x00\x09NONE@test'
            b'\x00'
            b'\x00\x00\x00\x06no-msg'
            b'\x00\x00\x00\x05en-us'
        )
        self.state = State()


class TestTCPIPForwardRequest(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_GLOBAL_REQUEST)
        self.request_name = String(GLOBAL_REQUEST_TCPIP_FORWARD)
        self.want_reply = Boolean(False)
        self.address = String(b'127.0.0.1')
        self.port = UInt32(65535)

        self.args = (self.want_reply, self.address, self.port)
        self.cls = connection.TCPIPForwardRequest
        self.packed = (
            b'\x50'
            b'\x00\x00\x00\x0Dtcpip-forward'
            b'\x00'
            b'\x00\x00\x00\x09127.0.0.1'
            b'\x00\x00\xFF\xFF'
        )
        self.state = State()

    def test_setstate_noreply(self):
        inst = self.cls(*self.args)
        inst.setstate(self.state)
        assert self.state.request_name == GLOBAL_REQUEST_TCPIP_FORWARD

    def test_setstate_reply(self):
        inst = self.cls(Boolean(True), *self.args[1:])
        inst.setstate(self.state)
        assert self.state.request_name == GLOBAL_REQUEST_TCPIP_FORWARD_REPLY


class TestTCPIPForwardCancel(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_GLOBAL_REQUEST)
        self.request_name = String(GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)
        self.want_reply = Boolean(False)
        self.address = String(b'127.0.0.1')
        self.port = UInt32(65535)

        self.args = (self.want_reply, self.address, self.port)
        self.cls = connection.TCPIPForwardCancel
        self.packed = (
            b'\x50'
            b'\x00\x00\x00\x14cancel-tcpip-forward'
            b'\x00'
            b'\x00\x00\x00\x09127.0.0.1'
            b'\x00\x00\xFF\xFF'
        )
        self.state = State()


class TestTCPIPForwardSuccess(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_REQUEST_SUCCESS)
        self.request_name = String(GLOBAL_REQUEST_TCPIP_FORWARD)

        self.args = ()
        self.cls = connection.TCPIPForwardSuccess
        self.packed = (
            b'\x51'
        )
        self.state = State(request_name=GLOBAL_REQUEST_TCPIP_FORWARD)


class TestTCPIPForwardSuccessAssigned(unittest.TestCase, BaseConnection):
    def setUp(self):
        self.header = Byte(SSH_MSG_REQUEST_SUCCESS)
        self.request_name = String(GLOBAL_REQUEST_TCPIP_FORWARD)
        self.port = UInt32(65535)

        self.args = (self.port,)
        self.cls = connection.TCPIPForwardSuccessAssigned
        self.packed = (
            b'\x51'
            b'\x00\x00\xFF\xFF'
        )
        self.state = State(request_name=GLOBAL_REQUEST_TCPIP_FORWARD_REPLY)
