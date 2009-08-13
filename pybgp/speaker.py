
import struct

from twisted.internet import reactor, protocol, task
from twisted.python import log

from pybgp import nlri, pathattr, proto

class BGP(protocol.Protocol):

    def connectionMade(self):
        self.buffer = ''
        self.holdtime = 60
        self.keepalive = None
        self.expiry = None

        open = proto.Open(asnum=64580, bgpid='155.198.51.97', holdtime=self.holdtime)
        open.caps['mbgp'] = (
                dict(afi=1,safi=1),
                dict(afi=1,safi=128),
                )
        open.caps['refresh'] = ['']

        print open

        self.send(open)

    def connectionLost(self, reason):
        log.err(reason)
        if self.expiry:
            self.expiry.cancel()
        if self.keepalive:
            self.keepalive.stop()

    def dataReceived(self, data):
        self.buffer += data

        while True:
            if len(self.buffer) < 19:
                return
            auth, length, type = struct.unpack('!16sHB', self.buffer[:19])
            if len(self.buffer) < length:
                return

            msg = self.buffer[:length]
            self.buffer = self.buffer[length:]

            msg = self.parse_msg(msg)

            self.handle_msg(msg)

    def parse_msg(self, msg):
        auth, length, type = struct.unpack('!16sHB', msg[:19])
        payload = msg[19:]
        del msg

        if type==1:
            return proto.Open.from_bytes(payload)

        elif type==2:
            return proto.Update.from_bytes(payload)

        elif type==3:
            return proto.Notification.from_bytes(payload)

        elif type==4:
            return proto.Keepalive.from_bytes(payload)

        else:
            raise Exception('invalid message')

    def send(self, msg):
        body = msg.encode()
        msg = struct.pack('!16sHB', '\xff'*16, 19+len(body), msg.number) + body
        self.transport.write(msg)

    def handle_msg(self, msg):
        if msg.kind=='open':

            self.holdtime = min(self.holdtime, msg.holdtime)

            # setup the function to send keepalives
            self.keepalive = task.LoopingCall(self.send_keepalive)
            interval = self.holdtime / 2
            self.keepalive.start(interval)

            # setup the expiry timer
            self.expiry = reactor.callLater(self.holdtime, self.expired)

        elif msg.kind=='keepalive':
            if self.expiry:
                self.expiry.reset(self.holdtime)

        elif msg.kind=='update':
            print "update"
            print msg

    def expired(self):
        self.keepalive.stop()
        self.keepalive = None

        log.msg('hold timer expired')
        self.transport.loseConnection()

    def send_keepalive(self):
        self.send(proto.Keepalive())
