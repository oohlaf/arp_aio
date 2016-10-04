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


logging.basicConfig(
    level=logging.DEBUG,
    format='%(name)s: %(message)s',
    stream=sys.stderr,
    )
log = logging.getLogger('main')


@asyncio.coroutine
def _create_raw_connection_transport(self, sock, protocol_factory):
    sock.setblocking(False)
    protocol = protocol_factory()
    waiter = asyncio.Future(loop=self)
    transport = self._make_socket_transport(sock, protocol, waiter)

    try:
        yield from waiter
    except:
        transport.close()
        raise

    return transport, protocol


@asyncio.coroutine
def create_raw_connection(self, protocol_factory, interface=None, *,
                          family=None, proto=0, sock=None):
    if interface is not None:
        interface = interface[:15]
        if sock is not None:
            raise ValueError(
                'device and sock can not be specified at the same time')

        if family is None:
            family = socket.AF_PACKET

        exceptions = []
        try:
            sock = socket.socket(family=family,
                                 type=socket.SOCK_RAW,
                                 proto=proto)
            sock.setblocking(False)
            try:
                sock.bind((interface, socket.SOCK_RAW))
                self._interface = interface
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
    elif sock is None:
        raise ValueError(
            'interface was not set and no sock specified')

    transport, protocol = yield from self._create_raw_connection_transport(
        sock, protocol_factory)

    return transport, protocol


setattr(asyncio.base_events.BaseEventLoop, '_create_raw_connection_transport', _create_raw_connection_transport)
setattr(asyncio.base_events.BaseEventLoop, 'create_raw_connection', create_raw_connection)


SIOCGIFADDR = 0x8915
SIOCSIFHWADDR = 0x8927


class ARPRequestProtocol(asyncio.Protocol):

    def __init__(self, ip, loop):
        self.ip = ip
        self.loop = loop
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
            interface = pack('256s', self.loop._interface.encode('ascii'))
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
            interface = pack('256s', self.loop._interface.encode('ascii'))
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
    coro = event_loop.create_raw_connection(
        lambda: ARPRequestProtocol(ip='192.168.1.64', loop=event_loop),
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
