
import array
import struct
import socket

from odict import OrderedDict as OD

class NLRI:
    def __init__(self, afi, safi, val):
        self.afi = afi
        self.safi = safi
        self.val = val

    def encode(self):
        return self.val

class vpnv4(NLRI):
    def __init__(self, labels, rd, prefix):
        self.labels = labels
        self.rd = rd
        self.prefix = prefix

    def __repr__(self):
        if self.labels:
            l = ','.join([str(l) for l in self.labels])
        else:
            l = 'none'

        return '<vpnv4 label %s rd %s prefix %s>' % (l, self.rd, self.prefix)

    def __str__(self):
        return '%s:%s' % (self.rd, self.prefix)

    def __cmp__(self, other):
        if isinstance(other, vpnv4):
            return cmp(
                    (self.labels, self.rd, self.prefix),
                    (other.labels, other.rd, other.prefix),
                    )
        return -1


    def encode(self):
        plen = 0
        v = ''
        labels = self.labels[:]

        if not labels:
            return '\0'

        labels = [l<<4 for l in labels]
        labels[-1] |= 1

        for l in labels:
            lo = l & 0xff
            hi = (l & 0xffff00) >> 8
            v += struct.pack('>HB', hi, lo)
            plen += 24

        l, r = self.rd.split(':')
        if '.' in l:
            ip = socket.inet_aton(l)
            rd = struct.pack('!H4sH', 1, ip, int(r))
        else:
            rd = struct.pack('!HHI', 0, int(l), int(r))

        v += rd
        plen += 64

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_aton(ip)
        masklen = int(masklen)

        plen += masklen
        if masklen > 24:
            v += ip
        elif masklen > 16:
            v += ip[:3]
        elif masklen > 8:
            v += ip[:2]
        elif masklen > 0:
            v += ip[:1]
        else:
            pass

        return struct.pack('B', plen) + v

    @classmethod
    def from_bytes(cls, plen, val):

        if plen==0:
            # what the hell?
            return cls([], '0:0', '0.0.0.0/0')

        idx = 0

        # plen is the length, in bits, of all the MPLS labels, plus the 8-byte RD, plus the IP prefix
        labels = []
        while True:
            ls, = struct.unpack_from('3s', val, idx)
            idx += 3
            plen -= 24

            if ls=='\x80\x00\x00':
                # special null label for vpnv4 withdraws
                labels = None
                break

            label, = struct.unpack_from('!I', '\x00'+ls)
            bottom = label & 1

            labels.append(label >> 4)
            if bottom:
                break

        rdtype, rd = struct.unpack_from('!H6s', val, idx)
        if rdtype==1:
            rdip, num = struct.unpack('!4sH', rd)
            rdip = socket.inet_ntoa(rdip)
            rd = '%s:%s' % (rdip, num)
        else:
            num1, num2 = struct.unpack('!HI', rd)
            rd = '%s:%s' % (num1, num2)

        idx += 8
        plen -= 64

        ipl = pb(plen)
        ip = val[idx:idx+ipl]
        idx += ipl

        prefix = pip(ip, plen)

        return cls(labels, rd, prefix)

class ipv4(NLRI):
    def __init__(self, prefix):
        self.prefix = prefix

    def __cmp__(self, other):
        if isinstance(other, ipv4):
            aip, alen = self.prefix.split('/')
            alen = int(alen)
            aip = socket.inet_aton(aip)

            bip, blen = other.prefix.split('/')
            blen = int(blen)
            bip = socket.inet_aton(bip)

            return cmp((aip,alen),(bip,blen))

        return -1

    def encode(self):
        plen = 0
        v = ''

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_aton(ip)
        masklen = int(masklen)

        plen += masklen
        if masklen > 24:
            v += ip
        elif masklen > 16:
            v += ip[:3]
        elif masklen > 8:
            v += ip[:2]
        elif masklen > 0:
            v += ip[:1]
        else:
            pass

        return struct.pack('B', plen) + v

    def __repr__(self):
        return '<ipv4 %s>' % (self.prefix,)

    def __str__(self):
        return self.prefix

    @classmethod
    def from_bytes(cls, plen, val):
        return cls(pip(val, plen))


def pb(masklen):
    if masklen > 24:
        return 4
    elif masklen > 16:
        return 3
    elif masklen > 8:
        return 2
    elif masklen > 0:
        return 1
    return 0

def pip(pi, masklen):
    pi += '\x00\x00\x00\x00'
    return '%s/%s' % (socket.inet_ntoa(pi[:4]), masklen)


def parse(bytes, afi=1, safi=0):
    rv = []

    if afi==1 and safi==128:
        klass = vpnv4
    else:
        klass = ipv4

    idx = 0
    while idx < len(bytes):
        plen, = struct.unpack_from('B', bytes, idx)
        idx += 1
        nbytes, rest = divmod(plen, 8)
        if rest:
            nbytes += 1
        val = bytes[idx:idx+nbytes]
        idx += nbytes

        rv.append(klass.from_bytes(plen, val))

    return rv
