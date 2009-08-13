
import struct
import socket

from odict import OrderedDict as OD


from pybgp import nlri, pathattr

class Open:
    kind = 'open'
    number = 1

    def __init__(self, bgpid, asnum, holdtime=180, version=4):
        self.version = version
        self.holdtime = holdtime
        self.asnum = asnum
        self.bgpid = bgpid
        self.caps = OD()
        self.params = OD()

    def from_bytes(cls, bytes):
        self = cls(None, None)

        assert len(bytes) >= 10, "open message must have 10 bytes"


        
        self.version, self.asnum, self.holdtime, bgpid, paramlen = struct.unpack_from('!BHH4sB', bytes)
        self.bgpid = socket.inet_ntoa(bgpid)
        if paramlen==0:
            return

        assert len(bytes) == 10 + paramlen, "message too short?"

        offset = 10
        while offset < len(bytes):
            type, plen = struct.unpack_from('BB', bytes, offset)
            offset += 2
            value = bytes[offset:offset+plen]
            offset += plen

            if type==2:
                # capabilities
                idx = 0
                while idx < len(value):
                    kind, clen = struct.unpack_from('BB', value, idx)
                    idx += 2
                    cap = value[idx:idx+clen]
                    idx += clen

                    if kind==1:
                        kind = 'mbgp'
                        iidx = 0
                        afi, reserved, safi = struct.unpack_from('!HBB', cap)
                        cap = dict(afi=afi, safi=safi)
                    elif kind==2:
                        kind = 'refresh'
                    elif kind==64:
                        kind = 'graceful-restart'
                    elif kind==65:
                        kind = '4byteas'
                        cap, = struct.unpack('!I', cap)

                    if kind in self.caps:
                        self.caps[kind].append(cap)
                    else:
                        self.caps[kind] = [cap]
            else:
                self.params[type] = value

        return self
    from_bytes = classmethod(from_bytes)

    def encode(self):
        params = ''
        for k,v in self.params.items():
            params += struct.pack('BB', k, len(v))
            params += v

        for c,vv in self.caps.items():
            if c=='mbgp':
                c = 1
            elif c=='refresh':
                c = 2
            elif c=='graceful-restart':
                c = 64
            elif c=='4byteas':
                c = 65

            for v in vv:
                if c==1:
                    v = struct.pack('!HH', v['afi'], v['safi'])
                elif c==65:
                    v = struct.pack('!I', v)

                cap = struct.pack('BB', c, len(v)) + v
                params += struct.pack('BB', 2, len(cap)) + cap

        bgpid = socket.inet_aton(self.bgpid)
        return struct.pack('!BHH4sB', self.version, self.asnum, self.holdtime, bgpid, len(params)) + params

    def __str__(self):
        s = 'Open message ver=%s as#=%s hold=%s peer=%s' % (
                self.version,
                self.asnum,
                self.holdtime,
                self.bgpid,
                )
        for p,v in self.params.items():
            s += ' param %s=%r' % (p,v)
        for c,v in self.caps.items():
            s += ' cap %s=%r' % (c,v)
        return s

class Keepalive:
    kind = 'keepalive'
    number = 4

    def from_bytes(cls, bytes):
        self = cls()

        return self
    from_bytes = classmethod(from_bytes)

    def encode(self):
        return ''

    def __str__(self):
        return 'Keepalive message'

class Notification:
    kind = 'notification'
    number = 3

    REASONS = {
        (1,1): 'not synchronised',
        (1,2): 'bad message len',
        (1,3): 'bad message type',
        (2,1): 'unsupported version',
        (2,2): 'bad peer AS',
        (2,3): 'bad BGP identifier',
        (2,4): 'unsupported optional param',
        (2,5): 'authentication failure',
        (2,6): 'unacceptable hold time',
        (3,1): 'malformed attribute list',
        (3,2): 'unrecognized well-known attr',
        (3,3): 'missing well-known attr',
        (3,4): 'attribute flags error',
        (3,5): 'attribute length error',
        (3,6): 'invalid origin attr',
        (3,7): 'as routing loop',
        (3,8): 'invalid next hop attr',
        (3,9): 'operational attribute error',
        (3,10): 'invalid network field',
    }

    def from_bytes(cls, bytes):
        self = cls()

        self.code, self.subcode = struct.unpack_from('BB', bytes)
        self.data = bytes[2:]

        return self
    from_bytes = classmethod(from_bytes)

    def __str__(self):
        c, s = self.code, self.subcode
        if (c,s) in self.REASONS:
            return 'Notification "%s" params %r' % (self.REASONS[c,s], self.data)
        return 'Notification message code=%d subcode=%d params=%r' % (self.code, self.subcode, self.data)

class Update:
    kind = 'update'
    number = 2

    def __init__(self, *pathattr, **kw):
        self.nlri = []
        self.withdraw = []
        self.pathattr = OD()

        for n in kw.pop('nlri', []):
            if isinstance(n, str):
                n = nlri.ipv4(n)
            self.nlri.append(n)

        for w in kw.pop('withdraw', []):
            if isinstance(w, str):
                w = nlri.ipv4(w)
            self.withdraw.append(w)

        self.pathattr = OD()
        for p in pathattr:
            self.pathattr[p.type] = p

    def from_bytes(cls, bytes):
        self = cls()

        d = {}

        idx = 0
        for kind in ('withdraw', 'pathattr'):
            plen, = struct.unpack_from('!H', bytes, idx)
            idx += 2
            d[kind] = bytes[idx:idx+plen]
            idx += plen

        self.nlri = nlri.parse(bytes[idx:])
        self.withdraw = nlri.parse(d['withdraw'])

        self.pathattr = OD()

        idx = 0
        bytes = d['pathattr']

        while idx < len(bytes):

            used, pattr = pathattr.decode(bytes, idx)
            idx += used
            self.pathattr[pattr.type] = pattr

        return self
    from_bytes = classmethod(from_bytes)

    def __repr__(self):
        s =  '<Update message withdraw=%r' % (self.withdraw,)
        for type,p in self.pathattr.items():
            s += '\n path attr %s' % (p,)
            if type=='mp-reach-nlri':
                for n in p.value['nlri']:
                    s += '\n  nlri=%s' % (n,)
        for n in self.nlri:
            s += '\n nlri %s' % (n,)

        s += '>'

        return s

    def __cmp__(self, other):
        if isinstance(other, Update):
            return cmp(
                    (self.pathattr, self.withdraw, self.nlri),
                    (other.pathattr, other.withdraw, other.nlri),
                    )
        return -1

    def encode(self):
        v = ''

        w = ''
        for n in self.withdraw:
            w += n.encode()

        v += struct.pack('!H', len(w))
        v += w

        p = ''
        for kind, attr in self.pathattr.items():
            p += attr.encode()
        v += struct.pack('!H', len(p))
        v += p

        for n in self.nlri:
            v += n.encode()

        return v

