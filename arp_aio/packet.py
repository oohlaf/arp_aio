#!/usr/bin/python3

import ipaddress
import logging

import macaddress

from struct import pack, unpack


log = logging.getLogger(__name__)


ETHERTYPE = {
    'IPv4': 0x0800,
    'ARP': 0x0806,
    'WOL': 0x0842,
    }

ARP_HTYPE = {
    'ETHERNET': 0x0001,
    }

ARP_HLEN = {
    'ETHERNET': 0x0006,
    }

ARP_PLEN = {
    'IPv4': 0x0004,
    }

ARP_OPER = {
    'REQUEST': 0x0001,
    'REPLY': 0x0002,
    }


class Ethernet:
    def __init__(self, frame=None, dst_mac=None, src_mac=None,
                 ethertype=None, payload=None):
        """Constructs an Ethernet frame either from a binary frame argument, or
        from the individual parameters.
        """
        if frame is not None:
            self.parse(frame)
        else:
            if isinstance(dst_mac, macaddress.MACAddress):
                self.dst_mac = dst_mac
            else:
                self.dst_mac = macaddress.MACAddress(dst_mac)
            if isinstance(src_mac, macaddress.MACAddress):
                self.src_mac = src_mac
            else:
                self.src_mac = macaddress.MACAddress(src_mac)
            self.ethertype = ETHERTYPE[ethertype]
            self.payload = payload

    def parse(self, frame):
        """Parse binary frame."""
        header = unpack('!6s6sH', frame[0:14])
        self.dst_mac = macaddress.MACAddress(header[0])
        self.src_mac = macaddress.MACAddress(header[1])
        self.ethertype = header[2]
        self.payload = frame[14:]

    def write(self):
        """Return the binary Ethernet frame."""
        fmt = '!6s6sH'
        header = pack(fmt,
                      self.dst_mac.packed,
                      self.src_mac.packed,
                      self.ethertype)
        frame = b''.join([header, self.payload])
        return frame

    def info(self):
        "Return text info on Ethernet frame."""
        return 'MAC destination: {:s}\n' \
               'MAC source: {:s}\n' \
               'EtherType: {:02X}\n' \
               'Payload length: {:d}'.format(str(self.dst_mac),
                                             str(self.src_mac),
                                             self.ethertype,
                                             len(self.payload)
                                             )


class ARP:
    def __init__(self, packet=None, htype=None, ptype=None,
                 oper=None, sha=None, spa=None, tha=None, tpa=None):
        """Construct an ARP packet from binary packet data, or construct it
        manually from the other arguments.
        """
        if packet is not None:
            self.parse(packet)
        else:
            if htype is None:
                htype = 'ETHERNET'
            self.htype = ARP_HTYPE[htype]
            self.hlen = ARP_HLEN[htype]
            if ptype is None:
                ptype = 'IPv4'
            self.ptype = ETHERTYPE[ptype]
            self.plen = ARP_PLEN[ptype]
            if oper is None:
                oper = 'REQUEST'
            self.oper = ARP_OPER[oper]
            if isinstance(sha, macaddress.MACAddress):
                self.sha = sha
            else:
                self.sha = macaddress.MACAddress(sha)
            if isinstance(tha, macaddress.MACAddress):
                self.tha = tha
            else:
                self.tha = macaddress.MACAddress(tha)
            if isinstance(spa, ipaddress.IPv4Address):
                self.spa = spa
            else:
                self.spa = ipaddress.IPv4Address(spa)
            if isinstance(tpa, ipaddress.IPv4Address):
                self.tpa = tpa
            else:
                self.tpa = ipaddress.IPv4Address(tpa)

    def parse(self, packet):
        """Parse binary ARP packet data."""
        header = unpack('!HHBB', packet[0:6])
        self.htype = header[0]
        if self.htype != ARP_HTYPE['ETHERNET']:
            msg = 'Unsupported ARP hardware type %d'
            raise ValueError(msg % self.htype)
        self.ptype = header[1]
        if self.ptype != ETHERTYPE['IPv4']:
            msg = 'Unsupported ARP protocol type %d'
            raise ValueError(msg % self.ptype)
        self.hlen = header[2]
        self.plen = header[3]
        log.debug('hlen={}'.format(self.hlen))
        log.debug('plen={}'.format(self.plen))
        if self.hlen != ARP_HLEN['ETHERNET']:
            msg = 'Unsupported ARP hardware length %d'
            raise ValueError(msg % self.hlen)
        if self.plen != ARP_PLEN['IPv4']:
            msg = 'Unsupported ARP protocol length %d'
            raise ValueError(msg % self.plen)
        fmt = '!H{:d}s{:d}s{:d}s{:d}s'.format(self.hlen, self.plen,
                                              self.hlen, self.plen)
        log.debug('fmt={}'.format(fmt))
        size = 8 + ((self.hlen + self.plen) * 2)
        log.debug('size={}'.format(size))
        data = unpack(fmt, packet[6:size])
        self.oper = data[0]
        self.sha = macaddress.MACAddress(data[1])
        self.spa = ipaddress.IPv4Address(data[2])
        self.tha = macaddress.MACAddress(data[3])
        self.tpa = ipaddress.IPv4Address(data[4])

    def write(self):
        """Return binary ARP packet data."""
        fmt = '!HHBBH{:d}s{:d}s{:d}s{:d}s'.format(self.hlen, self.plen,
                                                  self.hlen, self.plen)
        frame = pack(fmt,
                     self.htype, self.ptype,
                     self.hlen, self.plen,
                     self.oper,
                     self.sha.packed, self.spa.packed,
                     self.tha.packed, self.tpa.packed)
        return frame

    def info(self):
        """Return text info on ARP packet."""
        return 'hardware type: {:02X}\n' \
               'protocol type: {:02X}\n' \
               'hardware address length: {:01X}\n' \
               'protocol address length: {:01X}\n' \
               'operation: {:02X}\n' \
               'sender hardware address: {:s}\n' \
               'sender protocol address: {:s}\n' \
               'target hardware address: {:s}\n' \
               'target protocol address: {:s}'.format(self.htype,
                                                      self.ptype,
                                                      self.hlen,
                                                      self.plen,
                                                      self.oper,
                                                      str(self.sha),
                                                      str(self.spa),
                                                      str(self.tha),
                                                      str(self.tpa)
                                                      )


def main():
    a = ARP(sha='11:22:33:44:55:66', spa='1.2.3.4',
            tha='66:55:44:33:22:11', tpa='4.3.2.1')
    print(a.info())
    data = a.write()
    f = Ethernet(dst_mac='11:22:33:44:55:66', src_mac='66:55:44:33:22:11',
                 ethertype='ARP', payload=data)
    print(f.info())
    f.write()


if __name__ == '__main__':
    main()
