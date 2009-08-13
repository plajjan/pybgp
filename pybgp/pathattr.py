
import struct
import socket

from pybgp import nlri

def decode(bytes, idx=0):
    flagb, type = struct.unpack_from('BB', bytes, idx)
    idx += 2
    used = 2

    if flagb & 16:
        length, = struct.unpack_from('>H', bytes, idx)
        idx += 2
        used += 2
    else:
        length, = struct.unpack_from('!B', bytes, idx)
        idx += 1
        used += 1


    vl = bytes[idx:idx+length]
    used += length

    if type==1:
        obj = Origin.from_bytes(vl)
    elif type==2:
        obj = AsPath.from_bytes(vl)
    elif type==3:
        obj = NextHop.from_bytes(vl)
    elif type==4:
        obj = Med.from_bytes(vl)
    elif type==5:
        obj = LocalPref.from_bytes(vl)
    elif type==9:
        obj = Originator.from_bytes(vl)
    elif type==10:
        obj = ClusterList.from_bytes(vl)
    elif type==14:
        obj = MpReachNlri.from_bytes(vl)
    elif type==16:
        obj = ExtCommunity.from_bytes(vl)
    else:
        obj = PathAttr(type, vl)

    obj.flags = flagb
        
    return used, obj

class PathAttr:
    flags = 0

    def __init__(self, type, val):
        self.value = val
        self.typenum = type
        self.type = 'type-%s' % (type,)

    def packvalue(self):
        return self.value

    def __repr__(self):
        return '<%s type/num=%s/%s flags %x value %r>' % (
                self.__class__.__name__,
                self.type, self.typenum,
                self.flags,
                self.value,
                )

    def encode(self):
        fl = self.flags
        vl = self.packvalue()

        if len(vl) > 255:
            fl = fl | 16
            return struct.pack('!BBH', fl, self.typenum, len(vl)) + vl

        fl = fl & (0xff ^ 16)
        return struct.pack('BBB', fl, self.typenum, len(vl)) + vl

    def __cmp__(self, other):
        if isinstance(other, PathAttr):
            if other.__class__==self.__class__:
                return cmp(self.value, other.value)
            else:
                return -1

        return cmp(self.value, other)

class Origin(PathAttr):
    typenum = 1
    type = 'origin'

    def __init__(self, val='incomplete'):
        self.value = val

    def from_bytes(cls, val):
        value = val


        if value=='\x00':
            value = 'igp'
        elif value=='\x01':
            value = 'egp'
        elif value=='\x02':
            value = 'incomplete'

        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        if self.value=='igp':
            return '\x00'
        elif self.value=='egp':
            return '\x01'
        elif self.value=='incomplete':
            return '\x02'
        return self.value

class AsPath(PathAttr):
    typenum = 2
    type = 'aspath'

    def __init__(self, val):
        self.value = val

    def __repr__(self):
        s = '<aspath'
        for v in self.value:
            if isinstance(v, set):
                s += ' set('
                s += ','.join([
                    str(asnum) for asnum in v
                    ])
                s += ')'
            else:
                s += ' '
                s += ','.join([
                    str(asnum) for asnum in v
                    ])
        s += '>'
        return s

    def from_bytes(cls, val):
        value = []
        iidx = 0

        while iidx < len(val):
            segtype, numas = struct.unpack_from('BB', val, iidx)
            iidx += 2

            if segtype==1:
                v = set()
                add = v.add

            elif segtype==2:
                v = []
                add = v.append

            else:
                raise Exception('unknown segment type')

            for i in range(numas):
                asnum, = struct.unpack_from('!H', val, iidx)
                iidx += 2

                add(asnum)

            value.append(v)

        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        v = ''
        for seg in self.value:
            if isinstance(seg, set):
                segtype = 1
            elif isinstance(seg, (tuple, list)):
                segtype = 2
            else:
                raise Exception('unknown segment type %r' % (seg,))


            v += struct.pack('BB', segtype, len(seg))
            for asnum in seg:
                v += struct.pack('!H', asnum)
        return v

class NextHop(PathAttr):
    typenum = 3
    type = 'nexthop'

    def __init__(self, val):
        self.value = val

    def __repr__(self):
        return '<nexthop %s>' % (self.value,)

    def from_bytes(cls, val):
        return cls(socket.inet_ntoa(val))
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        return socket.inet_aton(self.value)

class IntAttr(PathAttr):
    def __init__(self, val=0):
        self.value = val

    def __repr__(self):
        return '<%s %d>' % (self.__class__.__name__, self.value)

    def from_bytes(cls, val):
        value, = struct.unpack_from('!I', val)
        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        return struct.pack('!I', self.value)

class Med(IntAttr):
    type = 'med'
    typenum = 4

class LocalPref(IntAttr):
    type = 'localpref'
    typenum = 5

class Originator(PathAttr):
    type = 'originator'
    typenum = 9
    def __init__(self, val):
        self.value = val

    def from_bytes(cls, val):
        if len(val)==4:
            value = socket.inet_ntoa(val)
        else:
            raise Exception('invalid originator')

        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        return socket.inet_aton(self.value)

class ClusterList(PathAttr):
    typenum = 10
    type = 'cluster-list'

    def __init__(self, val):
        self.value = val

    def from_bytes(cls, val):
        value = []
        iidx = 0
        while iidx < len(val):
            value.append(
                    socket.inet_ntoa(
                        struct.unpack_from('4s', val, iidx)[0]
                        )
                    )
            iidx += 4
        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        v = ''
        for c in self.value:
            v += socket.inet_aton(c)
        return v

class MpReachNlri(PathAttr):
    typenum = 14
    type = 'mp-reach-nlri'
    def __init__(self, val):
        self.value = val

    def __repr__(self):
        return '<MpReachNlri afi=%d safi=%d nh=%r %d nlri>' % (
                self.value['afi'],
                self.value['safi'],
                self.value['nh'],
                len(self.value['nlri']),
                )

    def from_bytes(cls, val):
        afi, safi, nhlen = struct.unpack_from('!HBB', val)

        nh = val[4:4+nhlen]
        if afi==1 and safi==128:
            # vpnv4
            rdlo, rdhi, nhip = struct.unpack('!II4s', nh)
            nh = socket.inet_ntoa(nhip)

        n = nlri.parse(val[4+nhlen:], afi, safi)

        return cls(dict(afi=afi, safi=safi, nh=nh, nlri=n))
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        afi = self.value['afi']
        safi = self.value['safi']
        if afi==1 and safi==128:
            nh = '\0'*8
            nh += socket.inet_aton(self.value['nh'])
        else:
            nh = self.value['nh']

        v = struct.pack('!HBB', afi, safi, len(nh))
        v += nh
        for n in self.value['nlri']:
            v += n.encode()
        return v

class ExtCommunity(PathAttr):
    typenum = 16
    type = 'extcommunity'

    def __init__(self, val=[]):
        self.value = val

    def from_bytes(cls, val):
        value = []
        iidx = 0
        while iidx < len(val):
            etype, esubtype, payload = struct.unpack_from('BB6s', val, iidx)

            if etype in (0,2) and esubtype==2:
                asnum, i = struct.unpack('!HI', payload)
                value.append(
                        'RT:%s:%s' % (asnum, i)
                        )
            elif etype==1 and esubtype==2:
                ip, i = struct.unpack('!4sH', payload)
                ip = socket.inet_ntoa(ip)
                value.append(
                        'RT:%s:%s' % (ip, i)
                        )
            else:
                value.append(
                        '%s:%s' % (etype, val[iidx+1:iidx+8].encode('hex'))
                        )

            iidx += 8
        return cls(value)
    from_bytes = classmethod(from_bytes)

    def packvalue(self):
        o = ''
        for v in self.value:
            k,v = v.split(':', 1)
            if k=='RT':
                l,h = v.split(':')
                if '.' in l:
                    ip = socket.inet_aton(l)
                    o += struct.pack('!BB4sH', 1, 2, ip, int(h))
                else:
                    o += struct.pack('!BBHI', 0, 2, int(l), int(h))
            else:
                o += struct.pack('B', int(k))
                o += v.decode('hex')
        return o
