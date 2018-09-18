"""
An extremely primitive bus usable interface for Bus Pirate's
binary I/O interface.
"""

import struct

DEBUGGING = False

def hexdump(data):
    """Pretty print a hex dump of data, similar to xxd"""
    lines = []
    offset = 0
    while offset < len(data):
        piece = data[offset:offset + 16]
        bytes = ''.join([('%02x ' % ord(x)) for x in piece])
        chars = ''.join([(x if 0x20 < ord(x) < 0x7f else '.') for x in piece])
        lines.append('%04x  %-24s %-24s %-16s' % (offset, bytes[:24], bytes[24:], chars))
        offset += len(piece)
    return "\n".join(lines)


class BusPirateError(Exception):
    pass

# http://dangerousprototypes.com/docs/Bitbang
class BusPirate(object):
    """
    Main object encapsulating Bus Pirate's interface.
    """
    def __init__(self, port):
        self._port = port
        self._enter_bbio()
        
    def __enter__(self):
        return self
        
    def __exit__(self, type, value, traceback):
        self._leave_bbio()

    def _read(self, count):
        """Read wrapper for bus interfaces"""
        data = self._port.read(count)
        if DEBUGGING:
            print "READ:"
            print hexdump(data)
        return data
        
    def _write(self, data):
        """Write wrapper for bus interfaces"""
        if DEBUGGING:
            print "WRITE:"
            print hexdump(data)
        self._port.write(data)
        
    def _write_byte(self, data):
        self._write(chr(data))
        
    def _timeout(self, value):
        self._port.timeout = value
        
    def _enter_bbio(self):
        """Switch to the bit-bang mode"""
        self._timeout(0.5)
        # Send the "reset to BBIO" command and check the response
        self._write("\x00")
        if self._check_for_bbio():
            return
        # Retry as documented
        # NOTE: a more robust procedure should be implemented
        self._write("\x00" * 19)
        if self._check_for_bbio():
            # Flush the input
            while self._read(512):
                pass
            return
        # No luck
        raise BusPirateError("out of sync")
        
    def _check_for_bbio(self):
        """Check the bit-bang mode response"""
        data = self._read(5)
        if len(data) != 5 or data[:4] != 'BBIO':
            return False
        version = data[4]
        return True
        
    def _leave_bbio(self):
        """Switch to the normal menu-driven mode"""
        # Send the BP reset command
        self._write("\x0F")
        # Should have received the response here but no real need...
    
    def spi(self):
        """Instantiate the SPI interface"""
        return SPI(self)

class BusController(object):
    """Base class for specific bus types"""
    def __init__(self, bp):
        self._bp = bp
        
    def __enter__(self):
        return self
        
    def __exit__(self, type, value, traceback):
        self.cleanup()
        
    def cleanup(self):
        """Cleanup actions when this object is destroyed"""
        self._bp._write("\x00")
        if not self._bp._check_for_bbio():
            raise BusPirateError("switching to raw mode failed")
            
    def _check_ok(self):
        """Reads and checks the response to a previosly submitted command"""
        if self._bp._read(1) != "\x01":
            raise BusPirateError("command failed")
            
    def _write_and_check_ok(self, data):
        self._bp._write_byte(data)
        self._check_ok()
        
    def set_peripherals(self, power, pullups, aux, cs):
        """
        Configure the peripherals:
        - Power output (enable or disable)
        - Pull-up resistors (enable or disable)
        - AUX output (high/low output)
        - CS output (high/low output)
        """
        self._write_and_check_ok(0x40 | (int(power) << 3) | (int(pullups) << 2) | (int(aux) << 1) | int(cs))

# http://dangerousprototypes.com/docs/SPI_(binary)
class SPI(BusController):
    """Binary SPI mode API"""
    def __init__(self, bp):
        BusController.__init__(self, bp)
        self._enter_spi()
        
    def _enter_spi(self):
        self._bp._write("\x01")
        mode = self._bp._read(3)
        if mode != "SPI":
            raise BusPirateError("incorrect mode received: %s" % repr(mode))
        version = self._bp._read(1)
        if version != "1":
            raise BusPirateError("incorrect version received: %s" % repr(version))
            
    def set_speed(self, speed):
        """Configure the clock speed"""
        speeds = ["30k", "125k", "250k", "1M", "2M", "2M6", "4M", "8M"]
        value = speeds.index(speed)
        self._write_and_check_ok(0x60 | value)
        
    def set_config(self, hiZ, clk_idle, clk_edge, clk_sample):
        """
        Configure the bus
        - Whether output is HiZ or strongly driven on high
        - Clock idle phase
        - Clock edge
        - Sample time
        """
        self._write_and_check_ok(0x80 | (int(not hiZ) << 3) | (int(clk_idle) << 2) | (int(clk_edge) << 1) | int(clk_sample))
        
    def set_cs(self, state):
        """Control the CS output explicitly"""
        self._write_and_check_ok(0x02 | int(state))
        
    def exchange(self, data):
        """
        Perform a short SPI exchange.
        Bus Pirate performs an SPI transaction, sending and receiving data
        at the same time.
        """
        length = len(data)
        if length == 0:
            raise ValueError("data must be non-empty")
        if length > 16:
            raise ValueError("data must be no more than 16 bytes long")
            
        self._write_and_check_ok(0x10 | length)
        self._bp._write(data)
        data = self._bp._read(length)
        return data
        
    def transaction(self, output, input_length, auto_cs=True):
        """
        Perform a SPI bus transaction using the "Write then read" command.
        Lengths of input and output data can be different.
        CS control can be automatic (performed by BP).
        """
        length = len(output)
        if length > 4096 or input_length > 4096:
            raise ValueError("phase length cannot be greater than 4096 bytes")
        if input_length < 0:
            raise ValueError("phase length cannot be negative")
            
        if auto_cs:
            cmd = 0x04
        else:
            cmd = 0x05
            
        self._bp._write(struct.pack(">BHH", cmd, len(output), input_length))
        if output:
            self._bp._write(output)
        self._check_ok()
        data = self._bp._read(input_length)
        return data
# EOF
