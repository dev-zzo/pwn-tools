"""
STM32 Bootloader tool
See the following STMicro application notes:
* AN2606 for the general description
* AN3155 for the protocol

Dependencies:
* pySerial

"""

import binascii
import struct

import serial

def log(text):
    print(text)

# AN2606: 3.2 Bootloader identification
__bl_interfaces = [
    (),
    ( 'usart' ),
    ( 'usart', 'usart2' ),
    ( 'usart', 'can', 'dfu' ),
    
    ( 'usart', 'dfu' ),
    ( 'usart', 'i2c' ),
    ( 'i2c' ),
    ( 'usart', 'can', 'dfu', 'i2c' ),
    
    ( 'i2c', 'spi' ),
    ( 'usart', 'can', 'dfu', 'i2c', 'spi' ),
    ( 'usart', 'dfu', 'i2c' ),
    ( 'usart', 'i2c', 'spi' ),

    ( 'usart', 'spi' ),
    ( 'usart', 'dfu', 'i2c', 'spi' ),
]
# AN2606: 48 Device-dependent bootloader parameters
__products = {
    "\x04\x10": { 'name': "STM32F10xxxx (medium density)", 'flash_base': 0x08000000, 'flash_size': 0x20000, 'ram_base': 0x20000000, 'ram_size': 0x5000, 'ram_valid': 0x20000200 }
    # TODO: add more devices!
}

class BootloaderError(Exception):
    "Generic bootloader error"
    pass
class TimeoutError(BootloaderError):
    "Communications timeout"
    pass
class ProtocolError(BootloaderError):
    "Data exchange protocol error"
    pass
class CommandError(BootloaderError):
    "Command execution error"
    pass

ACK = "\x79"
NAK = "\x1F"

def _append_checksum(data):
    "Compute and append the checksum"

    cs = 0
    if len(data) == 1:
        cs = (~ord(data)) & 0xFF
    else:
        for x in data:
            cs ^= ord(x)
    return data + chr(cs)

class Stm32Bootloader(object):
    "Encapsulates the bootloader functionality"

    def __init__(self, port, autobaud=True):
        self._p = port
        if autobaud:
            self._run_autobaud()

    def _run_autobaud(self):
        "Automatic baud rate detection procedure"

        self._p.write("\x7F")
        if _receive_ack(self._p):
            log("Autobaud procedure successful (got ACK)")
        else:
            log("Autobaud procedure successful (got NAK; assuming baud rate is correct)")

    def _receive_bytes(self, count):
        "Receive N bytes from the port"

        buffer = ''
        while count > 0:
            chunk = self._p.read(count)
            if not chunk:
                raise TimeoutError("receiving data")
            buffer += chunk
            count -= len(chunk)
        return buffer

    def _receive_ack(self):
        "Receive and verify the ACK byte"

        ack = self._p.read()
        if not ack:
            raise TimeoutError("receiving ACK")
        if ack == ACK:
            return True
        if ack == NAK:
            return False
        raise ProtocolError("unexpected response: %02x" % ord(ack))

    def _send_data_check_ack(self, data):
        self._p.write(_append_checksum(data))
        return self._receive_ack()

    def _receive_data_check_ack(self, count):
        data = self._receive_bytes(count)
        if not self._receive_ack():
            raise ProtocolError("expected ACK; got NAK instead")
        return data

    def get_blinfo(self):
        "Retrieve the bootloader version and the list of supported commands"

        if not self._send_data_check_ack("\x00"):
            raise CommandError("command failed")
        count = struct.unpack('B', self._receive_bytes(1))[0] + 1
        rsp = self._receive_data_check_ack(count)
        version = ord(rsp[0]) & 0xFF
        supported_cmds = rsp[1:]
        return { 'version': version, 'supported_cmds': supported_cmds }

    def get_pid(self):
        "Retrieve the product ID (2 bytes currently)"

        if not self._send_data_check_ack("\x02"):
            raise CommandError("command failed")
        count = struct.unpack('B', self._receive_bytes(1))[0] + 1
        rsp = self._receive_data_check_ack(count)
        return rsp

    def read_memory(self, addr, count):
        "Read memory region"

        if not self._send_data_check_ack("\x11"):
            raise CommandError("read protection is enabled")
        if not self._send_data_check_ack(struct.pack('>I', addr)):
            raise CommandError("address is rejected by the device")
        if not self._send_data_check_ack(struct.pack('B', count - 1)):
            raise CommandError("count is rejected by the device")
        rsp = self._receive_bytes(count)
        return rsp

    def write_memory(self, addr, data):
        "Write memory region"
        
        if not self._send_data_check_ack("\x31"):
            raise CommandError("read protection is enabled")
        if not self._send_data_check_ack(struct.pack('>I', addr)):
            raise CommandError("address is rejected by the device")
        if not self._send_data_check_ack(struct.pack('B', len(data) - 1) + data):
            raise CommandError("checksum error")
        # NOTE: according to the diagram in AN3155, 
        # NAK is not sent if memory address is invalid

    def erase_memory(self, pages):
        "Erase memory pages"
        
        if not self._send_data_check_ack("\x43"):
            raise CommandError("read protection is enabled")
        if pages is None:
            # Whole device
            if not self._send_data_check_ack(struct.pack('>I', addr)):
                raise CommandError("address is rejected by the device")
        else:
            # Specific pages
            data = struct.pack('B%dB' % len(pages), len(pages) - 1, *pages)
            if not self._send_data_check_ack(data):
                raise CommandError("checksum error")

    def write_protect(self, sectors):
        "Apply write protection to flash sectors"
        
        if not self._send_data_check_ack("\x63"):
            raise CommandError("read protection is enabled")
        data = struct.pack('B%dB' % len(sectors), len(sectors) - 1, *sectors)
        if not self._send_data_check_ack(data):
            raise CommandError("checksum error")
        
    def write_unprotect(self):
        "Remove write protection from all flash"

        if not self._send_data_check_ack("\x73"):
            raise CommandError("read protection is enabled")
        self._receive_ack()
    
    def readout_protect(self):
        "Enable readout protection on the device"
        if not self._send_data_check_ack("\x82"):
            raise CommandError("read protection is enabled")
        self._receive_ack()

    def readout_unprotect(self):
        "Disable readout protection on the device"
        if not self._send_data_check_ack("\x92"):
            raise CommandError("something went wrong")
        self._receive_ack()

    def go(self, addr):
        "Start executing code from the specified address"

        if not self._send_data_check_ack("\x21"):
            raise CommandError("read protection is enabled")
        if not self._send_data_check_ack(struct.pack('>I', addr)):
            raise CommandError("address is rejected by the device")
# End

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        sys.exit(1)
    port = sys.argv[1]
    baudrate = 57600
    p = serial.Serial(port, baudrate, parity=serial.PARITY_EVEN, timeout=2)
    
    bl = Stm32Bootloader(p)
    blid = bl.get_blinfo()['version']
    log("Bootloader version: %02x" % blid)
    bl_ifs = __bl_interfaces[blid >> 4]
    log("Bootloader interfaces: %s" % str(bl_ifs))
    pid = bl.get_pid()
    log("Product ID: %s" % binascii.hexlify(pid))
    product = __products[pid]
    log("Product: %s" % product['name'])

    flash_base = product['flash_base']
    flash_size = product['flash_size']
    block_size = 0x100
    log("Dumping memory: %08x:%08x" % (flash_base, flash_base + flash_size))
    with open('flash_dump.bin', 'wb') as fp:
        for offset in xrange(0, flash_size, block_size):
            data = bl.read_memory(flash_base + offset, block_size)
            fp.write(data)
    log("Dumping completed")
# EOF
