#!/usr/bin/python

import socket
import unittest

from pybgp import pathattr, nlri

class TestOrigin(unittest.TestCase):
    def test_encode(self):
        orig = pathattr.Origin('igp')

        b = orig.encode()

        self.assertEqual(b, '\x40\x01\x01\x00')

    def test_decode(self):
        b = '\x40\x01\x01\x02'

        used, orig = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(orig, pathattr.Origin))

        self.assertEqual(orig.value, 'incomplete')

class TestAsPath(unittest.TestCase):
    def sample(self):
        shouldb = '\x40\x02'    # as path

        payload = '\x02\x02'    # as path
        payload += '\xff\xff'   # 65535
        payload += '\xff\xfe'   # 65534

        payload += '\x01\x02'    # as set
        payload += '\xde\xad'   # 57005
        payload += '\xbe\xef'   # 48879

        shouldb += chr(len(payload))
        shouldb += payload

        return shouldb

    def test_encode(self):
        aspath = pathattr.AsPath([
            [65535,65534],
            set([57005, 48879]),
            ])

        b = aspath.encode()

        self.assertEqual(b, self.sample())

    def test_decode(self):
        b = self.sample()

        used, aspath = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(aspath, pathattr.AsPath))

        self.assertEqual(aspath.value, [
            [65535,65534],
            set([57005,48879]),
            ])


class TestMed(unittest.TestCase):
    def test_encode(self):
        med = pathattr.Med(32)

        b = med.encode()
        self.assertEqual(b, '\x80\x04\x04\x00\x00\x00 ')

    def test_decode(self):
        b = '\x80\x04\x04\x00\x00\x00 '

        used, med = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(med, pathattr.Med))

        self.assertEqual(med.value, 32)

class TestExtCommunity(unittest.TestCase):
    def test_encode(self):
        ext = pathattr.ExtCommunity()
        ext.value.append(
                'RT:192.168.0.0:1'
                )

        b = ext.encode()

        self.assertEqual(b, '\x00\x10\x08\x01\x02\xc0\xa8\x00\x00\x00\x01')

    def test_decode(self):
        b = '\x00\x10\x08\x01\x02\xc0\xa8\x00\x00\x00\x01'

        used, ext = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(ext, pathattr.ExtCommunity))

        self.assertEqual(ext.value, ['RT:192.168.0.0:1'])

class TestMpReachNlri(unittest.TestCase):
    def test_encode(self):
        r = pathattr.MpReachNlri(dict(
            afi=1,
            safi=128,
            nh='192.168.1.1',
            nlri=[nlri.vpnv4([111,222,333], '192.168.0.0:2', '192.168.2.0/24')],
            ))

        b = r.encode()

        self.assertEqual(b, '\x00\x0e&\x00\x01\x80\x0c\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\x01\x00\xa0\x00\x06\xf0\x00\r\xe0\x00\x14\xd1\x00\x01\xc0\xa8\x00\x00\x00\x02\xc0\xa8\x02')

    def test_decode(self):
        nh = '\0'*8 + socket.inet_aton('192.168.1.1')

        payload = '\x00\x01'# afi
        payload += chr(128) # safi
        payload += chr(len(nh))
        payload += nh
        payload += chr(0)   # reserved

        prefix = '\x00\x06\xf0'     # mpls label 0x0006f
        prefix += '\x00\x0d\xe0'    # mpls label 0x000de
        prefix += '\x00\x14\xd1'    # mpls label 0x0014d & bottom of stack
        prefix += '\x00\x01\xc0\xa8\x00\x00\x00\x02'    # rd 192.168.0.0:2

        prefix += '\xc0\xa8\x02\x80'    # 192.168.2
        masklen = 25

        prefix_len = 3*24 + 8*8 + masklen

        payload += chr(prefix_len)
        payload += prefix

        b = '\x00\x0e'
        b += chr(len(payload))
        b += payload

        used, mpreach = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(mpreach, pathattr.MpReachNlri))

        self.assertEqual(mpreach.value['afi'], 1)
        self.assertEqual(mpreach.value['safi'], 128)
        self.assertEqual(mpreach.value['nh'], '192.168.1.1')
        self.assertEqual(mpreach.value['nlri'], [
            nlri.vpnv4(
                [0x6f, 0xde, 0x14d],
                '192.168.0.0:2',
                '192.168.2.128/25'
                )
            ]
            )

class TestMpUnreachNlri(unittest.TestCase):
    def test_encode(self):
        r = pathattr.MpUnreachNlri(dict(
            afi=1,
            safi=128,
            withdraw=[nlri.vpnv4([111,222,333], '192.168.0.0:2', '192.168.2.0/24')],
            ))

        b = r.encode()

        self.assertEqual(b, '\x00\x0f\x18\x00\x01\x80\xa0\x00\x06\xf0\x00\r\xe0\x00\x14\xd1\x00\x01\xc0\xa8\x00\x00\x00\x02\xc0\xa8\x02')

    def test_decode(self):
        payload = '\x00\x01'# afi
        payload += chr(128) # safi

        prefix = '\x80\x00\x00'     # mpls special no-label
        prefix += '\x00\x01\xc0\xa8\x00\x00\x00\x02'    # rd 192.168.0.0:2

        prefix += '\xc0\xa8\x02\x80'    # 192.168.2
        masklen = 25

        prefix_len = 24 + 8*8 + masklen

        payload += chr(prefix_len)
        payload += prefix

        b = '\x00\x0f'
        b += chr(len(payload))
        b += payload

        used, mpunreach = pathattr.decode(b)

        self.assertEqual(used, len(b))
        self.failUnless(isinstance(mpunreach, pathattr.MpUnreachNlri))

        self.assertEqual(mpunreach.value['afi'], 1)
        self.assertEqual(mpunreach.value['safi'], 128)
        self.assertEqual(mpunreach.value['withdraw'], [
            nlri.vpnv4(None, '192.168.0.0:2', '192.168.2.128/25')
            ]
            )
