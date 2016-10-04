#!/usr/bin/python3


MACLENGTH = 48


class MACAddress:

    __slots__ = ('_mac', '__weakref__')

    _ALL_ONES = (2**MACLENGTH) - 1
    _max_len = MACLENGTH

    def __init__(self, address):
        """Construct single MAC address.

        Address can be a string or integer representing the MAC address. It can
        also be the binary big endian network representation.
        """
        if isinstance(address, int):
            self._check_int_address(address)
            self._mac = address
            return
        if isinstance(address, bytes):
            self._check_packed_address(address, 6)
            self._mac = int.from_bytes(address, 'big')
            return
        addr_str = str(address)
        self._mac = self._mac_int_from_string(addr_str)

    def __int__(self):
        return self._mac

    def __str__(self):
        return str(self._string_from_mac_int(self._mac))

    @property
    def packed(self):
        return self.mac_int_to_packed(self._mac)

    @classmethod
    def _check_int_address(cls, address):
        if address < 0:
            msg = '%d (< 0) is not permitted as a MAC address'
            raise ValueError(msg % address)
        if address > cls._ALL_ONES:
            msg = '%d (>= 2**%d) is not permitted as a MAC address'
            raise ValueError(msg % (address, cls._max_len))

    @classmethod
    def _check_packed_address(cls, address, expected_len):
        address_len = len(address)
        if address_len != expected_len:
            msg = '%r (len %d != %d) is not permitted as an MAC address'
            raise ValueError(msg % (address, address_len, expected_len))

    @classmethod
    def _string_from_mac_int(cls, mac_int=None, sep=':'):
        if mac_int is None:
            mac_int = int(cls._mac)
        if mac_int > cls._ALL_ONES:
            raise ValueError('MAC address too large')
        return sep.join(['%02x' % char for char in mac_int.to_bytes(6, 'big')])

    @classmethod
    def _mac_int_from_string(cls, mac_str):
        if not mac_str:
            raise ValueError('Address cannot be empty')
        for sep in (':', '-', ' '):
            mac_str = mac_str.replace(sep, '')
        mac = int(mac_str, 16)
        cls._check_int_address(address=mac)
        return mac

    @classmethod
    def mac_int_to_packed(cls, address):
        try:
            return address.to_bytes(6, 'big')
        except OverflowError:
            raise ValueError('Address negative or too large for MAC address')


def main():
    #m = MACAddress(117965411581)
    #m = MACAddress('00:1b:77:49:54:fd')
    m = MACAddress('00:00:00:00:00:00')
    print(int(m))
    print(str(m))
    print(m.packed)


if __name__ == '__main__':
    main()
