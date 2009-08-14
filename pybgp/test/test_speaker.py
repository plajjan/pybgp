#!/usr/bin/python

import unittest

from pybgp import proto, speaker, nlri

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import testcommon

class FakeTransport:
    def __init__(self):
        self.value = StringIO()
        self.closed = False

    def write(self, b):
        self.value.write(b)

    def loseConnection(self):
        self.closed = True

    def reply(self):
        return self.value.getvalue()

class TestSpeakerError(unittest.TestCase):
    def notsync(self, byte=0xfe):
        invalid = chr(byte)
        invalid += '\xff'*15
        invalid += '\x00\x13'
        invalid += '\x01'

        return invalid

    def tooshort(self, len=0x12):
        invalid = '\xff'*16
        invalid += '\x00'
        invalid += chr(len)
        invalid += '\x01'

        return invalid

    def toolong(self, len=0x1001):
        invalid = '\xff'*16
        invalid += chr(len >> 8)
        invalid += chr(len & 0xff)
        invalid += '\x01'

        return invalid

    def badmsg(self, msgtype=0):
        invalid = '\xff'*16
        invalid += '\x00\x13'
        invalid += chr(msgtype)

        return invalid

    def setUp(self):
        self.proto = speaker.BGP()
        self.proto.makeConnection(FakeTransport())

    def test_parse_notsync(self):
        self.proto.dataReceived(
                self.notsync(0xee)
                )

        expect = '\xff'*16
        expect += '\x00'
        expect += chr(19+2)
        expect += '\x03'    # notification
        expect += '\x01'    # code
        expect += '\x01'    # subcode

        self.failUnless(self.proto.transport.closed)

        self.assertEquals(
                expect,
                self.proto.transport.reply(),
                )

    def test_parse_tooshort(self):
        invalid = self.tooshort(18)
        self.proto.dataReceived(
                invalid
                )

        expect = '\xff'*16
        expect += '\x00'
        expect += chr(19+4)
        expect += '\x03'    # notification
        expect += '\x01'    # code
        expect += '\x02'    # subcode
        expect += '\x00\x12'    # the bad len

        self.failUnless(self.proto.transport.closed)

        self.assertEquals(
                expect,
                self.proto.transport.reply(),
                )

    def test_parse_toolong(self):
        self.proto.dataReceived(
                self.toolong(0xbbff)
                )

        expect = '\xff'*16
        expect += '\x00'
        expect += chr(19+4)
        expect += '\x03'    # notification
        expect += '\x01'    # code
        expect += '\x02'    # subcode
        expect += '\xbb\xff'# the bad len

        self.failUnless(self.proto.transport.closed)

        self.assertEquals(
                expect,
                self.proto.transport.reply(),
                )

    def test_parse_badmsg(self):
        self.proto.dataReceived(
                self.badmsg(0xff)
                )

        expect = '\xff'*16
        expect += '\x00'
        expect += chr(19+3)
        expect += '\x03'    # notification
        expect += '\x01'    # code
        expect += '\x03'    # subcode
        expect += '\xff'    # msgtype

        self.failUnless(self.proto.transport.closed)

        self.assertEquals(
                expect,
                self.proto.transport.reply(),
                )

class TestSpeakerGood(unittest.TestCase):
    def open(self):
        msg = '\xff'*16
        msg += '\x00'
        msg += chr(29)
        msg += '\x01'       # open
        msg += '\x04'       # version
        msg += '\xde\xad'   # asnum 0xdead
        msg += '\xbe\xef'   # holdtime 0xbeef
        msg += '\xc0\xa8\x01\x01'   # bgpid 192.168.1.1
        msg += '\x00'       # no params

        return msg

    def update_w(self):
        msg = '\xff'*16
        msg += '\x00'
        msg += chr(30)
        msg += '\x02'       # update
        msg += '\x00\x07'   # withdrawn len
        msg += '\x19\xc0\xa8\x01\x00'   # 192.168.1/25
        msg += '\x08\x0a'   # 10/8
        msg += '\x00\x00'   # no pathattr

        return msg

    def setUp(self):
        self.msgs = []
        self.proto = speaker.BGP()
        self.proto.handle_msg = self.msgs.append
        self.proto.makeConnection(FakeTransport())

    def test_one(self):
        msg = self.open()

        self.proto.dataReceived(msg)

        # should still be alive
        self.failIf(self.proto.transport.closed)

        # we should have one message and all data used
        self.failUnless(len(self.msgs)==1)
        self.failUnless(self.proto.buffer=='')

        msg = self.msgs[0]

        self.failUnless(isinstance(msg, proto.Open))

        self.assertEqual(
                msg.kind, 'open'
                )
        self.assertEqual(msg.version, 4)
        self.assertEqual(msg.asnum, 0xdead)
        self.assertEqual(msg.holdtime, 0xbeef)
        self.assertEqual(msg.bgpid, '192.168.1.1')

    def test_two(self):
        msgs = self.open() + self.update_w()

        self.proto.dataReceived(msgs)

        # should still be alive
        self.failIf(self.proto.transport.closed)

        # we should have two messages and all data used
        self.failUnless(len(self.msgs)==2)
        self.failUnless(self.proto.buffer=='')

        open = self.msgs[0]
        withdraw = self.msgs[1]

        self.failUnless(isinstance(open, proto.Open))
        self.failUnless(isinstance(withdraw, proto.Update))

        self.assertEqual(withdraw.withdraw, [
                nlri.ipv4('192.168.1.0/25'),
                nlri.ipv4('10.0.0.0/8'),
                ])


