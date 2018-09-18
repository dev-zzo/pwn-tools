import buspirate
import serial
import time
import struct

class MX25L1606E:
    def __init__(self, spi):
        self._spi = spi
    def read_id(self):
        return self._spi.transaction("\x9F", 3)
    def read_status_reg(self):
        return self._spi.transaction("\x05", 1)
    def write_status_reg(self, value):
        return self._spi.transaction(struct.pack("BB", 0x01, value), 0)
    def read_sector(self, address):
        data = struct.pack("BBBB", 0x03, address >> 16, (address >> 8) & 0xFF, address & 0xFF)
        return self._spi.transaction(data, 4096)
    def read_sfdp(self):
        return self._spi.transaction("\x5A\x00\x00\x00\x00", 4096)
    def write_enable(self):
        return self._spi.transaction("\x06", 0)
    def write_disable(self):
        return self._spi.transaction("\x04", 0)
    def read_security_reg(self):
        return self._spi.transaction("\x2B", 1)
    def write_security_reg(self):
        return self._spi.transaction("\x2F", 0)
    def erase_sector(self, address):
        data = struct.pack("BBBB", 0x20, address >> 16, (address >> 8) & 0xFF, address & 0xFF)
        return self._spi.transaction(data, 0)
    def erase_block(self, address):
        data = struct.pack("BBBB", 0x52, address >> 16, (address >> 8) & 0xFF, address & 0xFF)
        return self._spi.transaction(data, 0)
    def erase_chip(self):
        return self._spi.transaction("\x60", 0)
    def program_page(self, address, data):
        if len(data) != 256:
            raise ValueError("page length must be 256 bytes")
        data = struct.pack("BBBB", 0x02, address >> 16, (address >> 8) & 0xFF, address & 0xFF) + data
        return self._spi.transaction(data, 0)

class MX25L51245G:
    def __init__(self, spi):
        self._spi = spi
    def read_id(self):
        return self._spi.transaction("\x9F", 3)
    def read_status_reg(self):
        return self._spi.transaction("\x05", 1)
    def write_status_reg(self, value):
        return self._spi.transaction(struct.pack("BB", 0x01, value), 0)
    def enter_32_bit(self):
        self._spi.transaction("\xB7", 0)
    def exit_32_bit(self):
        self._spi.transaction("\xE9", 0)
    def read_sector(self, address):
        data = struct.pack("BBBB", 0x03, address >> 16, (address >> 8) & 0xFF, address & 0xFF)
        return self._spi.transaction(data, 4096)
    def read_sector32(self, address):
        data = struct.pack(">BI", 0x13, address)
        return self._spi.transaction(data, 4096)

def dumpit(mx):
    addr = 0
    mx.enter_32_bit()
    with open("dump.bin", "wb") as fp:
        while addr < ((512 / 8) * 1024 * 1024):
            print "Reading sector at %08X" % (addr)
            data = mx.read_sector32(addr)
            fp.write(data)
            addr += 0x1000

if __name__ == "__main__":
    portname = "COM10"
    port = serial.Serial(portname, baudrate=115200, timeout=15)
    with buspirate.BusPirate(port) as bp:
        with bp.spi() as spi:
            spi.set_peripherals(True, False, True, True)
            spi.set_speed("2M")
            spi.set_config(False, 0, 1, 0)
            spi.set_cs(True)
            mx = MX25L51245G(spi)
            time.sleep(0.25)
            id = mx.read_id()
            print "ID: %02X %02X%02X" % (ord(id[0]), ord(id[1]), ord(id[2]))
            sr = mx.read_status_reg()
            print "SR: %02X" % ord(sr)
            dumpit(mx)
