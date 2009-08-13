#!/usr/bin/python2.5

from twisted.internet import reactor, protocol, task

class TcpProbeProt(protocol.Protocol):
    def connectionMade(self):
        self.factory.ok()
        self.transport.loseConnection()

class TcpProbe(protocol.ClientFactory):
    protocol = TcpProbeProt
    ok = 0

    def clientConnectionFailed(self, connector, reason):
        self.callback(False)

    def ok(self):
        self.ok = 1

    def clientConnectionLost(self, connector, reason):
        if self.ok:
            self.callback(True)
        else:
            self.callback(False)

class Checker:
    def __init__(self, host, port, localif=''):
        self.state = 'down'
        self.host = host
        self.port = port
        self.localif = localif
        self.timeout = 2

    def start(self, interval):
        self.task = task.LoopingCall(self.check_tcp)
        self.task.start(interval)

    def check_tcp(self):
        f = TcpProbe()
        f.callback = self.callback
        reactor.connectTCP(self.host, self.port, f, timeout=self.timeout, bindAddress=(self.localif,0))

    def callback(self, up):
        print "state", up
        if up:
            if self.state=='down':
                self.change('down', 'up')
            self.state = 'up'
        else:
            if self.state=='up':
                self.change('up', 'down')
            self.state = 'down'

    def change(self, old, new):
        print "state for %s:%s (from %s) changes from %s to %s" % (self.host, self.port, self.localif, old, new)
