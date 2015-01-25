"""Test for message base classes.
"""

from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

# requires that base_types work
from pyssh.base_types import Byte, UInt32
from pyssh.message import base
from pyssh.message import unpack_from

import pytest
import unittest
from io import BytesIO

class TestState(unittest.TestCase):
    def test_empty(self):
        state = base.State()
        assert state.matches({})

    def test_simple_match(self):
        state = base.State(auth_method=b'foo-method')
        assert state.matches({'auth_method': b'foo-method'})

    def test_multi_match(self):
        state = base.State(auth_method=b'foo-method', kex_method=b'foo-method')
        assert state.matches({'auth_method': b'foo-method'})

    def test_not_match(self):
        state = base.State(auth_method=b'foo-method')
        assert not state.matches({'auth_method': b'bar-method'})

    def test_not_multi_match(self):
        state = base.State(auth_method=b'foo-method', kex_method=b'foo-method')
        assert not state.matches({'auth_method': b'bar-method'})

    def test_invalid_satisfiers(self):
        state = base.State()
        with pytest.raises(RuntimeError):
            state.matches({'no_such_key': b''})


class TestMessage(unittest.TestCase):
    def setUp(self):
        self.demo_header = Byte(255)
        self.second_header = Byte(254)

    def tearDown(self):
        base.Message._registered.pop(self.demo_header, None)
        base.Message._registered.pop(self.second_header, None)

    def _create_simple(self):
        @base.Message.register(self.demo_header)
        class DemoClass(base.Message):
            SPEC = []
            def __init__(self):
                super(DemoClass, self).__init__(self.HEADER)
        return DemoClass

    def _create_complex(self):
        demo_header = self.demo_header
        @base.Message.register(self.demo_header)
        class DemoClass(base.Message):
            SPEC = [('foo', UInt32)]
            def __init__(self, foo):
                super(DemoClass, self).__init__(self.HEADER)
                self.foo = foo
        return DemoClass

    def _create_intermediate(self):
        class Intermediate(base.Message):
            SPEC = [('foo', UInt32)]
            def __init__(self, foo):
                super(Intermediate, self).__init__(self.HEADER)
                self.foo = foo

        @base.Message.register(self.demo_header)
        class DemoClass(Intermediate):
            pass

        @base.Message.register(self.second_header)
        class SecondClass(Intermediate):
            pass

        return DemoClass, SecondClass

    def _create_conditionals(self):
        @base.Message.register_conditional(self.demo_header)
        class DemoClass(base.Message):
            SATISFIERS = {'request_name': b'some-global'}
            SPEC = []
            def __init__(self):
                super(DemoClass, self).__init__(self.HEADER)

        @base.Message.register_conditional(self.demo_header)
        class SecondClass(base.Message):
            SATISFIERS = {'request_name': b'some-other-global'}
            SPEC = []
            def __init__(self):
                super(SecondClass, self).__init__(self.HEADER)

        return DemoClass, SecondClass

    def test_init(self):
        """Test Message init, even though it should never be called on its own."""
        msg = base.Message(self.demo_header)
        assert msg.header == self.demo_header

    def test_invalid_init(self):
        """Test __init__ with an invalid type fails with a TypeError"""
        header = UInt32(255)
        with pytest.raises(TypeError):
            msg = base.Message(header)

    def test_register_simple(self):
        """Test registering a simple class."""
        DemoClass = self._create_simple()
        assert base.Message.lookup(self.demo_header) is DemoClass

    def test_pack_simple(self):
        DemoClass = self._create_simple()
        demo_inst = DemoClass()
        assert demo_inst.pack() == self.demo_header.pack()

    def test_unpack_simple(self):
        DemoClass = self._create_simple()
        data = BytesIO(b'\xFF')
        unpacked = unpack_from(data, base.State())
        assert isinstance(unpacked, DemoClass)

    def test_register_complex(self):
        DemoClass = self._create_complex()
        assert base.Message.lookup(self.demo_header) is DemoClass

    def test_pack_complex(self):
        DemoClass = self._create_complex()
        demo_value = UInt32(2**32-1)
        demo_inst = DemoClass(demo_value)
        assert demo_inst.pack() == b'\xFF\xFF\xFF\xFF\xFF'

    def test_unpack_complex(self):
        DemoClass = self._create_complex()
        data = BytesIO(b'\xFF\xFF\xFF\xFF\xFF')
        unpacked = unpack_from(data, base.State())
        assert unpacked.foo == UInt32(2**32-1)
        assert isinstance(unpacked, DemoClass)

    def test_pack_complex_invalid(self):
        DemoClass = self._create_complex()
        demo_value = Byte(1)
        with pytest.raises(TypeError):
            msg = DemoClass(demo_value)

    def test_register_intermediate(self):
        DemoClass, SecondClass = self._create_intermediate()
        assert base.Message.lookup(self.demo_header) is DemoClass
        assert base.Message.lookup(self.second_header) is SecondClass

    def test_pack_intermediate(self):
        DemoClass, SecondClass = self._create_intermediate()
        demo_value = UInt32(2000)
        second_value = UInt32(500)
        demo_inst = DemoClass(demo_value)
        second_inst = SecondClass(second_value)
        assert demo_inst.pack() == b'\xFF\x00\x00\x07\xD0'
        assert second_inst.pack() == b'\xFE\x00\x00\x01\xF4'

    def test_unpack_intermediate(self):
        DemoClass, SecondClass = self._create_intermediate()
        data = BytesIO(b'\xFF\xFF\xFF\xFF\xFF')
        unpacked = unpack_from(data, base.State())
        assert isinstance(unpacked, DemoClass)
        assert unpacked.foo == UInt32(2**32-1)
        data = BytesIO(b'\xFE\x00\x00\x00\x00')
        unpacked = unpack_from(data, base.State())
        assert isinstance(unpacked, SecondClass)
        assert unpacked.foo == UInt32(0)

    def test_register_conditional(self):
        DemoClass, SecondClass = self._create_conditionals()
        found = base.Message.lookup(self.demo_header)
        assert isinstance(found, base.Conditional)
        assert len(found) == 2

    def test_pack_conditional(self):
        DemoClass, SecondClass = self._create_conditionals()
        demo_inst = DemoClass()
        second_inst = SecondClass()
        assert demo_inst.pack() == b'\xFF'
        assert second_inst.pack() == b'\xFF'

    def test_unpack_conditional(self):
        DemoClass, SecondClass = self._create_conditionals()
        data = BytesIO(b'\xFF')
        state = base.State(request_name=b'some-global')
        unpacked = unpack_from(data, state)
        assert isinstance(unpacked, DemoClass)
        data = BytesIO(b'\xFF')
        state = base.State(request_name=b'some-other-global')
        unpacked = unpack_from(data, state)
        assert isinstance(unpacked, SecondClass)

    def test_failed_lookup(self):
        with pytest.raises(base.UnknownMessageError):
            base.Message.lookup(self.demo_header)



class TestConditional(unittest.TestCase):
    def test_init(self):
        cond = base.Conditional('FOO', 'bar')
        assert cond.FOO == 'bar'

    def test_find_satisfying(self):
        class Foo(object):
            SATISFIERS = {'auth_method': b'bar'}

        cond = base.Conditional('FOO', 'bar')
        cond.append(Foo)
        state = base.State(auth_method=b'bar')
        assert cond.find_satisfying(state) is Foo

    def test_find_fail(self):
        cond = base.Conditional('FOO', 'bar')
        state = base.State(auth_method=b'bar')
        with pytest.raises(KeyError):
            cond.find_satisfying(state)

