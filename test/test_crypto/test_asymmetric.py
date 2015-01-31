from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import io
import unittest

import pytest

from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.backends import default_backend

from pyssh.crypto import asymmetric
from pyssh.base_types import MPInt, String



# pylint: disable=line-too-long
class BaseKeyTest(object):
    def test_init(self):
        inst = self.cls(pubkey=self.pubkey)
        return inst

    def test_pack_pubkey(self):
        inst = self.cls(pubkey=self.pubkey)
        assert inst.pack_pubkey() == self.expect
        return inst

    def test_unpack_pubkey(self):
        inst = self.cls()
        inst.unpack_pubkey(io.BytesIO(self.expect))
        inst.pubkey.public_numbers() == self.pubkey.public_numbers()
        return inst

    def test_invalid_unpack_pubkey(self):
        inst = self.cls()
        with pytest.raises(asymmetric.InvalidAlgorithm):
            inst.unpack_pubkey(io.BytesIO(self.invalid_stream))

    def test_verify(self):
        inst = self.cls(pubkey=self.pubkey)
        inst.verify_signature(self.expect_sig, self.to_sign)

    def test_sign(self):
        """Not all signatures are deterministic, so test that the sign is verifiable."""
        inst = self.cls(privkey=self.privkey)
        blob = inst.sign(self.to_sign)
        inst_2 = self.cls(pubkey=self.pubkey)
        inst_2.verify_signature(blob, self.to_sign)

# some 1024-bit generated values, including private keys
# use these to generate test data.

RSA_KEY_VALUES = {
    'p': 0xFE365B40CF1EEC795E6071C6BA9C3AA2CB55FF87D4164F730FD86FB91FC89B15A21A685E1070DF43869A8D45EB26E70B9AA48911BD10235401CAE0AE06DE66EF,
    'q': 0xFDEB92FB55F2C1BCD9F3711E4EE1BB5FF98FF7B2227B7E77FF9659826A6AEB6D5EDF56EF25B24C5F2A797A5F2D1E2C1B730900C75E2D192525D91ECED290CC1B,
    'd': 0xF643AF0EAEB880AD72CC457BCFC7BFF76EADA11061063BC5C54A4DDD49A43FE5BD4A4DF4D56BA26D329AA707A61DE49CF70D52FB64117FAAEED2DF4AD4C310D57FA436803ACF31B7839FB169F0F0DEE52831678F3F05DF5831556870842B58F5A534AA5FF5C8B1ABE64D84688A2B1BD83611F297D2CE7BE380E32FBACE02D961,
    'dmp1': 0xCAAC579092111B83A004D0711A725825566BD7F058DCF8B6C9994B6992B7833D7A2207B786F0167065AE6E97A1E5402B763D5BB2B2C35D072AEEAEB6D06F1C2D,
    'dmq1': 0x42FB49A293619E49BB14C4DA41E4BA10EF3C5312E295C11ED6854AC7645B200F91DF48877D62335347591436D728066A9745E0B6B6D91EB0F5F2F87586863BD1,
    'iqmp': 0x78D6A5798543514E213FE2FA28CEFEC0665117473AEC395FD2F07C4E77AD64044313A8A9E211A4A27614B7690C661638A38C73459A737F870803CE199DF80F4D,
    'e': 0x10001,
    'n': 0xFC25A60965DF3BD3070BC691486BD3548F5CC16038674530FD78FD4F8A42C8249798E3CEDE1E3C50D78E73E612634B64DDB59E1027787AD9B1DB6398283E183B21B3E390E84E6D519914961C5E19C7E58D9A7C75DAA021CDD1932C301A8CF98A945BBFD500CD7BA4D5D8E97F34B265AEFAE7A556F7E0797F619483AFE7EB4F35
}



DSA_KEY_VALUES = {
    'x': 0xC44B58313F03880311E25BB9552F02494D6CE34B,
    'y': 0x4641466135CF5D01D7E6A9193EE8F8701A23DAEA24B27A20076F7FA7B466011BD210678E512AAC2E8D40FE11DDA2D2F4CC60C94AD22A787468F748F378A69EF3C266AC82BB529B02A82AA8B93AA9F594852B7C986E9D670AB6F5344B56E4DD9EC66C753EDE909AA51FE8B3EFA98E747F0B234E82B2A64520C072AAD3AE6694A8,
    'g': 0x8C031332A4EE04BB056D0713934D4EC1982B1EE8EEF649A1593A85E32B2C346667A755DEFFF5F81E8E1DCA1E843E17B35C5B2F950A75901EDED522AD83086D7884BF51168B955A44F11D1A1390D30852F201C7D444D3A64F6AA8B4E3F4DB5A40298C30C8D196FEDA1DA3ED2DEC904ED0DC87560F09EC2CDF85DD98DDC6878424,
    'p': 0xA0B1A1441A2421B24E27D3725D7912612661D169374D337E85544B5B3971CCCF483EF25A1FE9EFC5D1B1ABA023CB1398BC4E6FC5BCB738657EB556DE51DBF2F9CE0E8ECDF407F17D033B88B2DADC834FA51A200A9D913A0DF248948949EF641E01FFDB60710D91644B8954CBCFCF482D369CD61AE52A3BAA06A7A7AA0C5F5659,
    'q': 0xC484CD903054137E3A71D7CBA49CA77A0C7FB523
}

class TestRSA(unittest.TestCase, BaseKeyTest):
    def setUp(self):
        pubnum = rsa.RSAPublicNumbers(0x10001, 0xFC25A60965DF3BD3070BC691486BD3548F5CC16038674530FD78FD4F8A42C8249798E3CEDE1E3C50D78E73E612634B64DDB59E1027787AD9B1DB6398283E183B21B3E390E84E6D519914961C5E19C7E58D9A7C75DAA021CDD1932C301A8CF98A945BBFD500CD7BA4D5D8E97F34B265AEFAE7A556F7E0797F619483AFE7EB4F35)
        privnum = rsa.RSAPrivateNumbers(
            0xFE365B40CF1EEC795E6071C6BA9C3AA2CB55FF87D4164F730FD86FB91FC89B15A21A685E1070DF43869A8D45EB26E70B9AA48911BD10235401CAE0AE06DE66EF,
            0xFDEB92FB55F2C1BCD9F3711E4EE1BB5FF98FF7B2227B7E77FF9659826A6AEB6D5EDF56EF25B24C5F2A797A5F2D1E2C1B730900C75E2D192525D91ECED290CC1B,
            0xF643AF0EAEB880AD72CC457BCFC7BFF76EADA11061063BC5C54A4DDD49A43FE5BD4A4DF4D56BA26D329AA707A61DE49CF70D52FB64117FAAEED2DF4AD4C310D57FA436803ACF31B7839FB169F0F0DEE52831678F3F05DF5831556870842B58F5A534AA5FF5C8B1ABE64D84688A2B1BD83611F297D2CE7BE380E32FBACE02D961,
            0xCAAC579092111B83A004D0711A725825566BD7F058DCF8B6C9994B6992B7833D7A2207B786F0167065AE6E97A1E5402B763D5BB2B2C35D072AEEAEB6D06F1C2D,
            0x42FB49A293619E49BB14C4DA41E4BA10EF3C5312E295C11ED6854AC7645B200F91DF48877D62335347591436D728066A9745E0B6B6D91EB0F5F2F87586863BD1,
            0x78D6A5798543514E213FE2FA28CEFEC0665117473AEC395FD2F07C4E77AD64044313A8A9E211A4A27614B7690C661638A38C73459A737F870803CE199DF80F4D,
            pubnum
        )
        self.pubkey = pubnum.public_key(default_backend())
        self.privkey = privnum.private_key(default_backend())
        self.cls = asymmetric.RSAAlgorithm
        self.expect = (
            b'\x00\x00\x00\x07ssh-rsa'
            b'\x00\x00\x00\x03\x01\x00\x01'
            b'\x00\x00\x00\x81\x00\xFC\x25\xA6\x09\x65\xDF\x3B\xD3\x07\x0B\xC6\x91\x48\x6B\xD3\x54\x8F\x5C\xC1\x60\x38\x67\x45\x30\xFD\x78\xFD\x4F\x8A\x42\xC8\x24\x97\x98\xE3\xCE\xDE\x1E\x3C\x50\xD7\x8E\x73\xE6\x12\x63\x4B\x64\xDD\xB5\x9E\x10\x27\x78\x7A\xD9\xB1\xDB\x63\x98\x28\x3E\x18\x3B\x21\xB3\xE3\x90\xE8\x4E\x6D\x51\x99\x14\x96\x1C\x5E\x19\xC7\xE5\x8D\x9A\x7C\x75\xDA\xA0\x21\xCD\xD1\x93\x2C\x30\x1A\x8C\xF9\x8A\x94\x5B\xBF\xD5\x00\xCD\x7B\xA4\xD5\xD8\xE9\x7F\x34\xB2\x65\xAE\xFA\xE7\xA5\x56\xF7\xE0\x79\x7F\x61\x94\x83\xAF\xE7\xEB\x4F\x35'
        )
        self.invalid_stream = (
            b'\x00\x00\x00\x07ssh-dss'
            b'\x00\x00\x00\x03\x01\x00\x01'
            b'\x00\x00\x00\x81\x00\xFC\x25\xA6\x09\x65\xDF\x3B\xD3\x07\x0B\xC6\x91\x48\x6B\xD3\x54\x8F\x5C\xC1\x60\x38\x67\x45\x30\xFD\x78\xFD\x4F\x8A\x42\xC8\x24\x97\x98\xE3\xCE\xDE\x1E\x3C\x50\xD7\x8E\x73\xE6\x12\x63\x4B\x64\xDD\xB5\x9E\x10\x27\x78\x7A\xD9\xB1\xDB\x63\x98\x28\x3E\x18\x3B\x21\xB3\xE3\x90\xE8\x4E\x6D\x51\x99\x14\x96\x1C\x5E\x19\xC7\xE5\x8D\x9A\x7C\x75\xDA\xA0\x21\xCD\xD1\x93\x2C\x30\x1A\x8C\xF9\x8A\x94\x5B\xBF\xD5\x00\xCD\x7B\xA4\xD5\xD8\xE9\x7F\x34\xB2\x65\xAE\xFA\xE7\xA5\x56\xF7\xE0\x79\x7F\x61\x94\x83\xAF\xE7\xEB\x4F\x35'
        )

        self.to_sign = b'sample test data'

        self.expect_sig = (
            b'\x00\x00\x00\x07ssh-rsa'
            b'\x00\x00\x00\x80\x0E\x10\x52\x02\x70\x51\x4C\xF3\x95\x95\xE4\x62\x13\x1D\x2F\x41\x94\xD2\x51\xB5\x95\xAE\x22\xD4\x75\xE4\xB7\x3F\x41\x90\xDE\x59\x19\x4B\x1D\xD9\x70\xCE\x30\xA1\xB3\x12\x7F\x97\x81\xFB\xAC\xEC\xC1\xE2\x01\xFE\x54\x05\x12\xAB\xEB\x76\x2E\xE2\xF5\x30\xAE\xF5\x5B\x52\xDE\x61\x0B\x74\xB3\x8F\xAF\xC4\x4A\x41\x7D\x44\x7D\x76\xC0\x13\x38\xA0\x4B\x8A\x9B\xAB\x64\x25\x72\x02\xF5\xD2\xAC\x3D\x39\xB5\xC1\xC4\x80\xB9\xF6\x77\x82\xA6\xDF\x41\xD2\xCA\x52\xC7\xC3\x58\xA1\xE0\x9E\x00\xA1\xEC\xA2\x5C\xE0\x5B\x7D\x83\xBB\x44'
        )
        self.invalid_sig = (
            b'\x00\x00\x00\x07ssh-dss'
            b'\x00\x00\x00\x80\x0E\x10\x52\x02\x70\x51\x4C\xF3\x95\x95\xE4\x62\x13\x1D\x2F\x41\x94\xD2\x51\xB5\x95\xAE\x22\xD4\x75\xE4\xB7\x3F\x41\x90\xDE\x59\x19\x4B\x1D\xD9\x70\xCE\x30\xA1\xB3\x12\x7F\x97\x81\xFB\xAC\xEC\xC1\xE2\x01\xFE\x54\x05\x12\xAB\xEB\x76\x2E\xE2\xF5\x30\xAE\xF5\x5B\x52\xDE\x61\x0B\x74\xB3\x8F\xAF\xC4\x4A\x41\x7D\x44\x7D\x76\xC0\x13\x38\xA0\x4B\x8A\x9B\xAB\x64\x25\x72\x02\xF5\xD2\xAC\x3D\x39\xB5\xC1\xC4\x80\xB9\xF6\x77\x82\xA6\xDF\x41\xD2\xCA\x52\xC7\xC3\x58\xA1\xE0\x9E\x00\xA1\xEC\xA2\x5C\xE0\x5B\x7D\x83\xBB\x44'
        )

class TestDSA(unittest.TestCase, BaseKeyTest):
    def setUp(self):
        params = dsa.DSAParameterNumbers(0xA0B1A1441A2421B24E27D3725D7912612661D169374D337E85544B5B3971CCCF483EF25A1FE9EFC5D1B1ABA023CB1398BC4E6FC5BCB738657EB556DE51DBF2F9CE0E8ECDF407F17D033B88B2DADC834FA51A200A9D913A0DF248948949EF641E01FFDB60710D91644B8954CBCFCF482D369CD61AE52A3BAA06A7A7AA0C5F5659,
                                         0xC484CD903054137E3A71D7CBA49CA77A0C7FB523,
                                         0x8C031332A4EE04BB056D0713934D4EC1982B1EE8EEF649A1593A85E32B2C346667A755DEFFF5F81E8E1DCA1E843E17B35C5B2F950A75901EDED522AD83086D7884BF51168B955A44F11D1A1390D30852F201C7D444D3A64F6AA8B4E3F4DB5A40298C30C8D196FEDA1DA3ED2DEC904ED0DC87560F09EC2CDF85DD98DDC6878424)
        pubnums = dsa.DSAPublicNumbers(0x4641466135CF5D01D7E6A9193EE8F8701A23DAEA24B27A20076F7FA7B466011BD210678E512AAC2E8D40FE11DDA2D2F4CC60C94AD22A787468F748F378A69EF3C266AC82BB529B02A82AA8B93AA9F594852B7C986E9D670AB6F5344B56E4DD9EC66C753EDE909AA51FE8B3EFA98E747F0B234E82B2A64520C072AAD3AE6694A8, params)
        privnums = dsa.DSAPrivateNumbers(0xC44B58313F03880311E25BB9552F02494D6CE34B, pubnums)
        self.pubkey = pubnums.public_key(default_backend())
        self.privkey = privnums.private_key(default_backend())
        self.expect = (
            b'\x00\x00\x00\x07ssh-dss'
            b'\x00\x00\x00\x81\x00\xA0\xB1\xA1\x44\x1A\x24\x21\xB2\x4E\x27\xD3\x72\x5D\x79\x12\x61\x26\x61\xD1\x69\x37\x4D\x33\x7E\x85\x54\x4B\x5B\x39\x71\xCC\xCF\x48\x3E\xF2\x5A\x1F\xE9\xEF\xC5\xD1\xB1\xAB\xA0\x23\xCB\x13\x98\xBC\x4E\x6F\xC5\xBC\xB7\x38\x65\x7E\xB5\x56\xDE\x51\xDB\xF2\xF9\xCE\x0E\x8E\xCD\xF4\x07\xF1\x7D\x03\x3B\x88\xB2\xDA\xDC\x83\x4F\xA5\x1A\x20\x0A\x9D\x91\x3A\x0D\xF2\x48\x94\x89\x49\xEF\x64\x1E\x01\xFF\xDB\x60\x71\x0D\x91\x64\x4B\x89\x54\xCB\xCF\xCF\x48\x2D\x36\x9C\xD6\x1A\xE5\x2A\x3B\xAA\x06\xA7\xA7\xAA\x0C\x5F\x56\x59'
            b'\x00\x00\x00\x15\x00\xC4\x84\xCD\x90\x30\x54\x13\x7E\x3A\x71\xD7\xCB\xA4\x9C\xA7\x7A\x0C\x7F\xB5\x23'
            b'\x00\x00\x00\x81\x00\x8C\x03\x13\x32\xA4\xEE\x04\xBB\x05\x6D\x07\x13\x93\x4D\x4E\xC1\x98\x2B\x1E\xE8\xEE\xF6\x49\xA1\x59\x3A\x85\xE3\x2B\x2C\x34\x66\x67\xA7\x55\xDE\xFF\xF5\xF8\x1E\x8E\x1D\xCA\x1E\x84\x3E\x17\xB3\x5C\x5B\x2F\x95\x0A\x75\x90\x1E\xDE\xD5\x22\xAD\x83\x08\x6D\x78\x84\xBF\x51\x16\x8B\x95\x5A\x44\xF1\x1D\x1A\x13\x90\xD3\x08\x52\xF2\x01\xC7\xD4\x44\xD3\xA6\x4F\x6A\xA8\xB4\xE3\xF4\xDB\x5A\x40\x29\x8C\x30\xC8\xD1\x96\xFE\xDA\x1D\xA3\xED\x2D\xEC\x90\x4E\xD0\xDC\x87\x56\x0F\x09\xEC\x2C\xDF\x85\xDD\x98\xDD\xC6\x87\x84\x24'
            b'\x00\x00\x00\x80\x46\x41\x46\x61\x35\xCF\x5D\x01\xD7\xE6\xA9\x19\x3E\xE8\xF8\x70\x1A\x23\xDA\xEA\x24\xB2\x7A\x20\x07\x6F\x7F\xA7\xB4\x66\x01\x1B\xD2\x10\x67\x8E\x51\x2A\xAC\x2E\x8D\x40\xFE\x11\xDD\xA2\xD2\xF4\xCC\x60\xC9\x4A\xD2\x2A\x78\x74\x68\xF7\x48\xF3\x78\xA6\x9E\xF3\xC2\x66\xAC\x82\xBB\x52\x9B\x02\xA8\x2A\xA8\xB9\x3A\xA9\xF5\x94\x85\x2B\x7C\x98\x6E\x9D\x67\x0A\xB6\xF5\x34\x4B\x56\xE4\xDD\x9E\xC6\x6C\x75\x3E\xDE\x90\x9A\xA5\x1F\xE8\xB3\xEF\xA9\x8E\x74\x7F\x0B\x23\x4E\x82\xB2\xA6\x45\x20\xC0\x72\xAA\xD3\xAE\x66\x94\xA8'
        )
        self.invalid_stream = (
            b'\x00\x00\x00\x07ssh-rsa'
            b'\x00\x00\x00\x81\x00\xA0\xB1\xA1\x44\x1A\x24\x21\xB2\x4E\x27\xD3\x72\x5D\x79\x12\x61\x26\x61\xD1\x69\x37\x4D\x33\x7E\x85\x54\x4B\x5B\x39\x71\xCC\xCF\x48\x3E\xF2\x5A\x1F\xE9\xEF\xC5\xD1\xB1\xAB\xA0\x23\xCB\x13\x98\xBC\x4E\x6F\xC5\xBC\xB7\x38\x65\x7E\xB5\x56\xDE\x51\xDB\xF2\xF9\xCE\x0E\x8E\xCD\xF4\x07\xF1\x7D\x03\x3B\x88\xB2\xDA\xDC\x83\x4F\xA5\x1A\x20\x0A\x9D\x91\x3A\x0D\xF2\x48\x94\x89\x49\xEF\x64\x1E\x01\xFF\xDB\x60\x71\x0D\x91\x64\x4B\x89\x54\xCB\xCF\xCF\x48\x2D\x36\x9C\xD6\x1A\xE5\x2A\x3B\xAA\x06\xA7\xA7\xAA\x0C\x5F\x56\x59'
            b'\x00\x00\x00\x15\x00\xC4\x84\xCD\x90\x30\x54\x13\x7E\x3A\x71\xD7\xCB\xA4\x9C\xA7\x7A\x0C\x7F\xB5\x23'
            b'\x00\x00\x00\x81\x00\x8C\x03\x13\x32\xA4\xEE\x04\xBB\x05\x6D\x07\x13\x93\x4D\x4E\xC1\x98\x2B\x1E\xE8\xEE\xF6\x49\xA1\x59\x3A\x85\xE3\x2B\x2C\x34\x66\x67\xA7\x55\xDE\xFF\xF5\xF8\x1E\x8E\x1D\xCA\x1E\x84\x3E\x17\xB3\x5C\x5B\x2F\x95\x0A\x75\x90\x1E\xDE\xD5\x22\xAD\x83\x08\x6D\x78\x84\xBF\x51\x16\x8B\x95\x5A\x44\xF1\x1D\x1A\x13\x90\xD3\x08\x52\xF2\x01\xC7\xD4\x44\xD3\xA6\x4F\x6A\xA8\xB4\xE3\xF4\xDB\x5A\x40\x29\x8C\x30\xC8\xD1\x96\xFE\xDA\x1D\xA3\xED\x2D\xEC\x90\x4E\xD0\xDC\x87\x56\x0F\x09\xEC\x2C\xDF\x85\xDD\x98\xDD\xC6\x87\x84\x24'
            b'\x00\x00\x00\x80\x46\x41\x46\x61\x35\xCF\x5D\x01\xD7\xE6\xA9\x19\x3E\xE8\xF8\x70\x1A\x23\xDA\xEA\x24\xB2\x7A\x20\x07\x6F\x7F\xA7\xB4\x66\x01\x1B\xD2\x10\x67\x8E\x51\x2A\xAC\x2E\x8D\x40\xFE\x11\xDD\xA2\xD2\xF4\xCC\x60\xC9\x4A\xD2\x2A\x78\x74\x68\xF7\x48\xF3\x78\xA6\x9E\xF3\xC2\x66\xAC\x82\xBB\x52\x9B\x02\xA8\x2A\xA8\xB9\x3A\xA9\xF5\x94\x85\x2B\x7C\x98\x6E\x9D\x67\x0A\xB6\xF5\x34\x4B\x56\xE4\xDD\x9E\xC6\x6C\x75\x3E\xDE\x90\x9A\xA5\x1F\xE8\xB3\xEF\xA9\x8E\x74\x7F\x0B\x23\x4E\x82\xB2\xA6\x45\x20\xC0\x72\xAA\xD3\xAE\x66\x94\xA8'
        )

        self.cls = asymmetric.DSAAlgorithm
        self.to_sign = b'sample test data'
        self.expect_sig = (
            b'\x00\x00\x00\x07ssh-dss'
            b'\x00\x00\x00\x28\x4B\x5E\xD1\x99\x58\xBB\x2F\xD5\xD0\xCC\x6E\x6B\x97\x3A\xD8\xA9\x73\xEA\xB7\xCB\x31\x34\x21\xEF\x51\x13\xB3\xE6\x3D\x3B\x4E\x3E\x2D\xA8\x4A\x74\xBB\x22\x83\x3D'
        )
        self.invalid_sig = (
            b'\x00\x00\x00\x07ssh-rsa'
            b'\x00\x00\x00\x28\x4B\x5E\xD1\x99\x58\xBB\x2F\xD5\xD0\xCC\x6E\x6B\x97\x3A\xD8\xA9\x73\xEA\xB7\xCB\x31\x34\x21\xEF\x51\x13\xB3\xE6\x3D\x3B\x4E\x3E\x2D\xA8\x4A\x74\xBB\x22\x83\x3D'
        )



_RSA_PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA5cGL6NasDwaQohX3wv+MN8lJT0acNrcl43zadFszSa4DPABj
tBoIRN11/AMSQbrpcHodOexUj2UDic92fQzhflg5rDfaKj9VVk41jUyHLfe/FHa4
LxXRSLB9wyEX2+9NWYL6bIK2ITrEudlY9gAUz+GOuYCxptdW6iupE5Y78U/bOuuI
t+KMSktVPg35O5UOY97UbAM2i+7Xhsf4gN6S14jD/MrUgmJ3FYxkIRh1BFbtAXqS
p9+3o/eD+Zq1rrRKi/12SwuGXbsqds+6+y+a7SgT1/ycqJySZo5S7JAE7CwQyMA3
8V87gSmYP7xVSva12BfE1swHUMwMwysMMvEVXwIDAQABAoIBAH1nbfExswokgC8o
JGq3xxXv9OajWMJ4puKLFEWsPcs6gqNuZv03tEm6QxrBpmZgGeh9jpQ+DU2TSiIf
LcJFlJK8nwYEGj0zAmYwHAS6v5H0hsQppJB2rRuq0Yn+9yHhdOullQBDPBvZEuWJ
34euNa3dpGRV/SFeqh74o7mAJ8mmzvb/OLA8ef40lJvMw99PO5CY0pszNtJ5V4Rj
YIfotR3tGxjogHEalM2bfAcWVwqKhusstw9MhrNOPcGQgziuOFyMoNwW3+XK9TW4
I1xJwXFyGS3WZAguQTNjBY48xilFutZAtchwg8FV/TQbVlKJ9Ltbz01toGedtNae
qzJe0PkCgYEA836Cszg/ewShgMlGZyEY576SqxOWNt1DQqSGFSGU7cUoBxNoxFCl
ywleWAp0uwvWCmFuTVZRXOwnHMwtHOVXtXLgz/w88rjKVM/O6ljbwNkUNRoq80Uo
/0t5qDDF4bQQJkaymgWcG5s+klWm49WHLixT/J309Zba7H9+Wpq+E8MCgYEA8Y5n
w0KcddM7WrDBtGIZxQQewiOwl9ApgKznyWYT3qKeRxWvfQcu+KpIPjzwcdUqxfjf
Hi3Ic7IlfOKKBkZI4xXpuFg2cOpgHsf6fOmoKoZUVSQtH9kiFEzILzN14wYZaRK/
0Rx9Vr9lTf7ONct02GyW2u2Ch3OFEmgiTqOzKjUCgYEAn17rjwA+1HboelHDCdco
5O3gM6cjR4+06VakCAqt3p6Pn2n9xZh/m4/rNzbIxnBtzOeOeYIIyQgsZXXiBSq7
KKEjMh6HidqXW8GUTeCRHP04c7VH7WgT+FzfKM2bhyoC8/qMBbGsRolq//6duDvX
Ocp7wjlkzqXJbsfX3Nexl18CgYAxtdu2vEuUl97cIAoNBC9HczydOVkLNQSFfY/J
y58FLzQhbt4JfeP1up1ZaZMV6gd+bGQGQufAn4XFeJ1tAyPWz9ikXkr9283iJ8dt
02wPLEvIpcQ/jKDNyqtbw1xcVxH9pKUi9Jj6tDK15V0shu1J6Lb24O/+zhAxpIqC
4n9pjQKBgGbwKO2qiq6+e/sER3LPHmBiBwW2ZuJYnMafmIz7lm7Ui2m2K7zccsJo
1gggVoc28sC/Q+C35dUiSouEiNuLMrOpgsRZXz8pAKCEH2T0GtvtP401UJ/UOkKi
Ji9+yT+jaTFUgOYp5Rzhmf6u5I7lCDhAeG0poxz/a89+ygKXsPy6
-----END RSA PRIVATE KEY-----"""

_RSA_PUBLIC_KEY = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlwYvo1qwPBpCiFffC/4w3yUlPRpw2tyXjfNp0WzNJrgM8AGO0GghE3XX8AxJBuulweh057FSPZQOJz3Z9DOF+WDmsN9oqP1VWTjWNTIct978UdrgvFdFIsH3DIRfb701ZgvpsgrYhOsS52Vj2ABTP4Y65gLGm11bqK6kTljvxT9s664i34oxKS1U+Dfk7lQ5j3tRsAzaL7teGx/iA3pLXiMP8ytSCYncVjGQhGHUEVu0BepKn37ej94P5mrWutEqL/XZLC4Zduyp2z7r7L5rtKBPX/JyonJJmjlLskATsLBDIwDfxXzuBKZg/vFVK9rXYF8TWzAdQzAzDKwwy8RVf jake@gandalf-the-grey"

_DSA_PRIVATE_KEY = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDOejpZoN4dfVle11IC10EYJWyjF6qinF/t63JqlsC2QLKV7qpI
SoJZC/xexRe2oR9O/+PY2sF5lwp0/bPbKkGbWTqcYiZE3TSzd7ZLO793tyOkod1M
rBwYlhQ6PuYxbDz5gfP9ryiddZDsJAg8J4JgHTowvJ3ycMWU6SnbTQxVWwIVAJIX
fjH0ZWXBYIhQRC2bZRwM0uS1AoGBAJLq5FYpl5vV+x7ECIcExSlcCIIv5j1y6+RQ
1JdSsXbthlGPS8VNFnnaXw/t3x/8wluH+MWIGUQm2MU9voVQ8xn1+cwNv63pODOn
AOPcp3+bA0u9qTROaGLLUNY2FuK7mrQZUGVFK49+IVPP5swtMDXdfVlcU237X8MQ
JUhXClJhAoGAZvxMxQSlVcsUo3H50VNf7xxyUPwpvYvBG+5qV6OUOQ3oEUFCzKKW
BvQ1r25q170ITRRxLqkWNuEB6DfALzv+oyWaHG6wAzXMHfFUaRtyR0Ddbp8xWYmC
qcqHUMrKDF0u8v2oPe4ocoyLXbpqKAyQ35/JEjJ4LjRRsnKdw9mx/78CFHCEM8De
S3LQ5d4dlcUzRQXUpcQW
-----END DSA PRIVATE KEY-----"""

_DSA_PUBLIC_KEY = b"ssh-dss AAAAB3NzaC1kc3MAAACBAM56Olmg3h19WV7XUgLXQRglbKMXqqKcX+3rcmqWwLZAspXuqkhKglkL/F7FF7ahH07/49jawXmXCnT9s9sqQZtZOpxiJkTdNLN3tks7v3e3I6Sh3UysHBiWFDo+5jFsPPmB8/2vKJ11kOwkCDwngmAdOjC8nfJwxZTpKdtNDFVbAAAAFQCSF34x9GVlwWCIUEQtm2UcDNLktQAAAIEAkurkVimXm9X7HsQIhwTFKVwIgi/mPXLr5FDUl1Kxdu2GUY9LxU0WedpfD+3fH/zCW4f4xYgZRCbYxT2+hVDzGfX5zA2/rek4M6cA49ynf5sDS72pNE5oYstQ1jYW4ruatBlQZUUrj34hU8/mzC0wNd19WVxTbftfwxAlSFcKUmEAAACAZvxMxQSlVcsUo3H50VNf7xxyUPwpvYvBG+5qV6OUOQ3oEUFCzKKWBvQ1r25q170ITRRxLqkWNuEB6DfALzv+oyWaHG6wAzXMHfFUaRtyR0Ddbp8xWYmCqcqHUMrKDF0u8v2oPe4ocoyLXbpqKAyQ35/JEjJ4LjRRsnKdw9mx/78= jake@gandalf-the-grey"

class Test_Readkey(unittest.TestCase):
    def test_load_public_rsa(self):
        inst = asymmetric.RSAAlgorithm()
        inst.read_pubkey(_RSA_PUBLIC_KEY)
        pubnum = inst.pubkey.public_numbers()
        assert pubnum.n == 0xE5C18BE8D6AC0F0690A215F7C2FF8C37C9494F469C36B725E37CDA745B3349AE033C0063B41A0844DD75FC031241BAE9707A1D39EC548F650389CF767D0CE17E5839AC37DA2A3F55564E358D4C872DF7BF1476B82F15D148B07DC32117DBEF4D5982FA6C82B6213AC4B9D958F60014CFE18EB980B1A6D756EA2BA913963BF14FDB3AEB88B7E28C4A4B553E0DF93B950E63DED46C03368BEED786C7F880DE92D788C3FCCAD4826277158C642118750456ED017A92A7DFB7A3F783F99AB5AEB44A8BFD764B0B865DBB2A76CFBAFB2F9AED2813D7FC9CA89C92668E52EC9004EC2C10C8C037F15F3B8129983FBC554AF6B5D817C4D6CC0750CC0CC32B0C32F1155F
        assert pubnum.e == 0x10001
        assert inst.pubkey

    def test_load_private_rsa(self):
        inst = asymmetric.RSAAlgorithm()
        inst.read_privkey(_RSA_PRIVATE_KEY)
        privnum = inst.privkey.private_numbers()
        assert privnum.p == 0xF37E82B3383F7B04A180C946672118E7BE92AB139636DD4342A486152194EDC528071368C450A5CB095E580A74BB0BD60A616E4D56515CEC271CCC2D1CE557B572E0CFFC3CF2B8CA54CFCEEA58DBC0D914351A2AF34528FF4B79A830C5E1B4102646B29A059C1B9B3E9255A6E3D5872E2C53FC9DF4F596DAEC7F7E5A9ABE13C3
        assert privnum.q == 0xF18E67C3429C75D33B5AB0C1B46219C5041EC223B097D02980ACE7C96613DEA29E4715AF7D072EF8AA483E3CF071D52AC5F8DF1E2DC873B2257CE28A064648E315E9B8583670EA601EC7FA7CE9A82A865455242D1FD922144CC82F3375E306196912BFD11C7D56BF654DFECE35CB74D86C96DAED828773851268224EA3B32A35
        assert privnum.d == 0x7D676DF131B30A24802F28246AB7C715EFF4E6A358C278A6E28B1445AC3DCB3A82A36E66FD37B449BA431AC1A6666019E87D8E943E0D4D934A221F2DC2459492BC9F06041A3D330266301C04BABF91F486C429A49076AD1BAAD189FEF721E174EBA59500433C1BD912E589DF87AE35ADDDA46455FD215EAA1EF8A3B98027C9A6CEF6FF38B03C79FE34949BCCC3DF4F3B9098D29B3336D2795784636087E8B51DED1B18E880711A94CD9B7C0716570A8A86EB2CB70F4C86B34E3DC1908338AE385C8CA0DC16DFE5CAF535B8235C49C17172192DD664082E413363058E3CC62945BAD640B5C87083C155FD341B565289F4BB5BCF4D6DA0679DB4D69EAB325ED0F9
        assert inst.privkey

    def test_load_public_dsa(self):
        inst = asymmetric.DSAAlgorithm()
        inst.read_pubkey(_DSA_PUBLIC_KEY)
        pubnum = inst.pubkey.public_numbers()
        assert inst.pubkey
        assert pubnum.y == 0x66FC4CC504A555CB14A371F9D1535FEF1C7250FC29BD8BC11BEE6A57A394390DE8114142CCA29606F435AF6E6AD7BD084D14712EA91636E101E837C02F3BFEA3259A1C6EB00335CC1DF154691B724740DD6E9F31598982A9CA8750CACA0C5D2EF2FDA83DEE28728C8B5DBA6A280C90DF9FC91232782E3451B2729DC3D9B1FFBF

    def test_load_private_dsa(self):
        inst = asymmetric.DSAAlgorithm()
        inst.read_privkey(_DSA_PRIVATE_KEY)
        privnum = inst.privkey.private_numbers()
        assert inst.privkey
        assert privnum.x == 0x708433C0DE4B72D0E5DE1D95C5334505D4A5C416

class TetGetPublicKey(unittest.TestCase):
    def test_unsupported(self):
        keytype = b'no-algorithm'
        with pytest.raises(asymmetric.UnsupportedKeyProtocol):
            asymmetric.get_asymmetric_algorithm(keytype)

    def test_ok(self):
        keytype = b'ssh-rsa'
        ret = asymmetric.get_asymmetric_algorithm(keytype)
        assert isinstance(ret, asymmetric.RSAAlgorithm)
