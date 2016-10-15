#!/usr/bin/python3

import asyncio
import fcntl
import ipaddress
import logging
import socket
import sys

from struct import pack, unpack

import macaddress

from packet import Ethernet, ARP, ETHERTYPE
from util import drop_privileges


logging.basicConfig(
    level=logging.DEBUG,
    format='%(name)s: %(message)s',
    stream=sys.stderr,
    )
log = logging.getLogger('main')


@asyncio.coroutine
def create_raw_connection(protocol_factory, loop,
                          interface=None, family=0, proto=0):
    if interface is None:
        raise ValueError(
            'interface was not set')
    else:
        interface = interface[:15]

    if family == 0:
        family = socket.AF_PACKET
    if proto != 0:
        proto = socket.htons(proto)

    exceptions = []
    sock = None
    try:
        sock = socket.socket(family=family,
                             type=socket.SOCK_RAW,
                             proto=proto)
        drop_privileges()
        sock.setblocking(False)
        try:
            sock.bind((interface, socket.SOCK_RAW))
        except OSError as exc:
            exc = OSError(
                    exc.errno, 'error while attempting to bind on '
                    'interface {!r}: {}'.format(
                        interface, exc.strerror.lower()))
            exceptions.append(exc)
    except OSError as exc:
        if sock is not None:
            sock.close()
        exceptions.append(exc)
    except:
        if sock is not None:
            sock.close()
        raise

    if len(exceptions) == 1:
        raise exceptions[0]
    elif len(exceptions) > 1:
        model = str(exceptions[0])
        if all(str(exc) == model for exc in exceptions):
            raise exceptions[0]
        raise OSError('Multiple exceptions: {}'.format(
            ', '.join(str(exc) for exc in exceptions)))

    transport, protocol = yield from loop._create_connection_transport(
        sock, protocol_factory, ssl=None, server_hostname=None)
    return transport, protocol


SIOCGIFADDR = 0x8915
SIOCSIFHWADDR = 0x8927


class ARPRequestProtocol(asyncio.Protocol):

    def __init__(self, ip):
        self.ip = ip
        self.transport = None
        self.src_mac = None
        self.src_ip = None

    def connection_made(self, transport):
        log.info('connection made')
        self.transport = transport
        frame = self.arp_request(self.ip)
        transport.write(frame)

    def connection_lost(self, exc):
        log.warning('connection lost')
        self.loop.stop()

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass

    def data_received(self, data):
        frame = Ethernet(frame=data)
        # skip frame unless ARP
        if frame.ethertype == ETHERTYPE['ARP']:
            log.info('data length is {}'.format(len(data)))
            log.debug('data received {}'.format(data))
            log.info(frame.info())
            packet = ARP(packet=frame.payload)
            log.info(packet.info())

    def eof_received(self):
        return False

    def _get_mac_info(self):
        """Return the MAC address of the interface. The result is cached for
        subsequent access.
        """
        if self.src_mac is not None:
            return self.src_mac
        else:
            sock = self.transport._sock
            interface = pack('256s', sock.getsockname()[0].encode('ascii'))
            info = fcntl.ioctl(sock.fileno(), SIOCSIFHWADDR, interface)
            self.src_mac = macaddress.MACAddress(info[18:24])
            return self.src_mac

    def _get_ip_info(self):
        """Return the IP address of the interface. The result is cached for
        subsequent access.
        """
        if self.src_ip is not None:
            return self.src_ip
        else:
            sock = self.transport._sock
            interface = pack('256s', sock.getsockname()[0].encode('ascii'))
            info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, interface)
            self.src_ip = ipaddress.IPv4Address(info[20:24])
            return self.src_ip

    def arp_request(self, ip):
        packet = ARP(tha='00:00:00:00:00:00', tpa=ip,
                     sha=self._get_mac_info(), spa=self._get_ip_info())
        frame = Ethernet(dst_mac='FF:FF:FF:FF:FF:FF',
                         src_mac=self._get_mac_info(),
                         ethertype='ARP',
                         payload=packet.write())
        log.info(frame.info())
        log.info(packet.info())
        return frame.write()


def main():
    event_loop = asyncio.get_event_loop()
    coro = create_raw_connection(
        lambda: ARPRequestProtocol(ip='192.168.1.64'),
        loop=event_loop,
        interface='eth0')
    server_transport, server_proto = event_loop.run_until_complete(coro)
    try:
        # event_loop.run_until_complete(coro)
        event_loop.run_forever()
    except KeyboardInterrupt:
        log.info('keyboard interrupt')
    finally:
        log.info('closing event loop')
        server_transport.close()
        event_loop.close()


if __name__ == '__main__':
    main()
