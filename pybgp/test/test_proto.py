#!/usr/bin/python

import unittest

from pybgp import proto, pathattr, nlri

class TestAttr(unittest.TestCase):
    def test_med(self):
        med = pathattr.Med(32)

        b = med.encode()
        i, med2 = pathattr.decode(b)

        self.assertEqual(med, med2)

    def test_extcomm(self):
        ext = pathattr.ExtCommunity()
        ext.value.append(
                'RT:155.198.0.0:1'
                )

        b = ext.encode()

        i, ext2 = pathattr.decode(b)

        self.assertEqual(ext, ext2)

    def test_mp_reach_nlri(self):
        r = pathattr.MpReachNlri(dict(
            afi=1,
            safi=128,
            nh='192.168.1.1',
            nlri=[nlri.vpnv4([111,222,333], '192.168.0.0:2', '155.198.1.0/24')],
            ))

        b = r.encode()

        i, r2 = pathattr.decode(b)

        self.assertEqual(r, r2)


class TestBGP(unittest.TestCase):
    def test_basic(self):
        b = '\x04\xfcD\x00\xb4\xc2R\x98\x0b.\x02\x06\x01\x04\x00\x01\x00\x01\x02\x06\x01\x04\x00\x01\x00\x80\x02\x02\x80\x00\x02\x02\x02\x00\x02\x0c@\n\x00x\x00\x01\x01\x00\x00\x01\x80\x00\x02\x06A\x04\x00\x00\xfcD'

        open = proto.Open.from_bytes(b)

        self.assertEqual(open.version, 4)
        self.assertEqual(open.asnum, 64580)
        self.assertEqual(open.holdtime, 180)
        self.assertEqual(open.bgpid, '194.82.152.11')

        # capabilities
        self.assertEqual(open.caps['refresh'], [''])
        self.assertEqual(open.caps['4byteas'], [64580])
        self.assertEqual(open.caps['mbgp'], [{'afi': 1, 'safi': 1}, {'afi': 1, 'safi': 128}])

        e = open.encode()


        self.assertEqual(b, e)

    def test_update(self):
        b = '\x00\x00\x00k@\x01\x01\x00@\x02\x08\x02\x03\xfcE\xfcD\xfc7\x80\x04\x04\x00\x00\x00\x00@\x05\x04\x00\x00\x00\xff\xc0\x10\x08\x01\x02\x9b\xc6\x00\x00\x00\x01\x80\n\x08\xc2R\x98\x0b\xc2R\x98\x01\x80\t\x04\xc2R\x98\x04\xc0\x14\x0e\x00\x01\x00\x01\x9b\xc6\x00\x00\x00\x01\xc2R\x98\x04\x80\x0e\x1d\x00\x01\x80\x0c\x00\x00\x00\x00\x00\x00\x00\x00\xc2R\x98\x04\x00X\x00\x07\x01\x00\x01\x9b\xc6\x00\x00\x00\x01'

        update = proto.Update.from_bytes(b)

        self.assertEqual(update.pathattr['origin'], 'igp')
        self.assertEqual(update.pathattr['med'], 0)
        self.assertEqual(update.pathattr['localpref'], 255)
        self.assertEqual(update.pathattr['extcommunity'], ['RT:155.198.0.0:1'])
        self.assertEqual(update.pathattr['originator'], '194.82.152.4')
        self.assertEqual(update.pathattr['cluster-list'], ['194.82.152.11', '194.82.152.1'])
        self.assertEqual(update.pathattr['aspath'], [[64581, 64580, 64567]])

        e = update.encode()
        update2 = proto.Update.from_bytes(e)

        self.assertEqual(update, update2)

