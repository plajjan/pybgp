import struct

class BgpExc(Exception):
    data = None

    send_error = True

    def __str__(self):
        return '<%s %r>' % (self.__class__.__name__, self.data)

class NotSync(BgpExc):
    code = 1
    subcode = 1


class BadLen(BgpExc):
    code = 1
    subcode = 2

    def __init__(self, msg, len):
        self.msg = msg
        self.len = len
        self.data = struct.pack('!H', len)

    def __str__(self):
        return '<BadLen %d msgtype=%d>' % (self.len,self.msg)

class BadMsg(BgpExc):
    code = 1
    subcode = 3

    def __init__(self, msg):
        self.msg = msg
        self.data = struct.pack('B', msg)

    def __str__(self):
        return '<BadMsg %d>' % (self.msg,)

