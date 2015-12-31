'''
A quite dumb IOCTL fuzzer.

TO DO list:

* Guard against drivers accepting arbitrary IOCTL code.
* Implement heuristic scan for input and output buffer sizes.
* Improve recording performance

Remainder on how control codes are built.

 3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
+-+-----------------------------+---+-+---------------------+---+
|C|       Device  Type          |RqA|c|    Function Code    |TrT|
+-+-----------------------------+---+-+---------------------+---+

C: Common bit
  Set for vendor-assigned Device Type values.

Device Type:
  Identifies the device type.
  Values of less than 0x8000 are reserved for Microsoft.

RqA: Required Access
  Indicates the type of access that a caller must request when opening
  the file object that represents the device.

c: Custom bit
  Set for vendor-assigned Function Code values.

Function Code:
  Identifies the function to be performed by the driver.
  Values of less than 0x800 are reserved for Microsoft.

TrT: Transfer Type
  Indicates how the system will pass data between the caller
  of DeviceIoControl and the driver that handles the IRP.
  See: https://msdn.microsoft.com/en-us/library/windows/hardware/ff540663%28v=vs.85%29.aspx

'''

import sys
import os
import ctypes
import argparse
import random
import time

#
# NT junk
#

NtOpenFile = ctypes.windll.ntdll.NtOpenFile
NtClose = ctypes.windll.ntdll.NtClose
NtAllocateVirtualMemory = ctypes.windll.ntdll.NtAllocateVirtualMemory
NtDeviceIoControlFile = ctypes.windll.ntdll.NtDeviceIoControlFile
SetConsoleTitle = ctypes.windll.kernel32.SetConsoleTitleA

FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002

FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116

FILE_SHARE_READWRITE = 3

FILE_ANY_ACCESS = 0x0000
FILE_READ_ACCESS = 0x0001
FILE_WRITE_ACCESS = 0x0002

METHOD_BUFFERED = 0
METHOD_NEITHER = 3

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040

BUFFER_BASE = 0x1000
buffer_ptr = ctypes.cast(0x1000, ctypes.POINTER(ctypes.c_byte))

def to_unsigned(x):
    if x < 0:
        return 0x80000000L | (x & 0x7FFFFFFFL)
    return long(x)

class NtError(Exception):
    def __init__(self, status):
        self.status = to_unsigned(status)
    def __str__(self):
        return 'NTSTATUS: %08X' % self.status
    def __repr__(self):
        return str(self)

class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
            ('a', ctypes.c_ulong),
            ('b', ctypes.c_ulong),
        ]

class UNICODE_STRING(ctypes.Structure):
    def __init__(self, s):
        bytes = len(s) * 2
        ss = unicode(s)
        ctypes.Structure.__init__(self, bytes, bytes + 2, ss)

    _fields_ = [
            ('Length', ctypes.c_ushort),
            ('MaximumLength', ctypes.c_ushort),
            ('Buffer', ctypes.c_wchar_p),
        ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    def __init__(self, name):
        self.__name = name
        self.__us_name = UNICODE_STRING(name)
        ctypes.Structure.__init__(self,
            ctypes.sizeof(self),
            None,
            ctypes.pointer(self.__us_name),
            0,
            None,
            None)

    _fields_ = [
            ('Length', ctypes.c_ulong),
            ('RootDirectory', ctypes.c_void_p),
            ('ObjectName', ctypes.POINTER(UNICODE_STRING)),
            ('Attributes', ctypes.c_ulong),
            ('SecurityDescriptor', ctypes.c_void_p),
            ('SecurityQualityOfService', ctypes.c_void_p),
        ]

IoStatusBlock = IO_STATUS_BLOCK()

def OpenFile(path, access):
    "Wrapper around NtOpenFile funkiness"

    oa = OBJECT_ATTRIBUTES(path)
    handle = ctypes.c_ulong(-1)
    status = NtOpenFile(ctypes.byref(handle),
        access,
        ctypes.byref(oa),
        ctypes.byref(IoStatusBlock),
        FILE_SHARE_READWRITE,
        0)
    status = to_unsigned(status)
    if status != 0:
        raise NtError(status)
    return handle

def DeviceIoControl(handle, ioctl, input_ptr, input_length, output_ptr, output_length):
    "Wrapper around NtDeviceIoControl funkiness"

    # Handle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
    status = NtDeviceIoControlFile(handle,
        None, None, None,
        ctypes.byref(IoStatusBlock),
        ioctl,
        input_ptr, input_length,
        output_ptr, output_length)
    return to_unsigned(status)

#
# SCANNING
#

def scan_ioctl(handle, ioctl_code):
    "Try to figure out additional info about the given IOCTL"

    # Check if IOCTL uses no inputs at all.
    status = DeviceIoControl(handle, ioctl_code, None, 0, None, 0)
    if status < 0x40000000L:
        print('  IOCTL responded with no error when no buffers were provided.')
        return
    # Try to figure out the input buffer minimum size
    status = DeviceIoControl(handle, ioctl_code, BUFFER_BASE, 0, BUFFER_BASE, 0x1000)
    if status == 0xC0000023L: # STATUS_BUFFER_TOO_SMALL
        size = 0
        while status == 0xC0000023L and size < 0x1000:
            size += 2
            status = DeviceIoControl(handle, ioctl_code, BUFFER_BASE, size, BUFFER_BASE, 0x1000)
        print('  Guesstimate of minimal input buffer size: %d bytes' % size)
    else:
        print('  Input buffer size probe returned %08X' % status)
    # Try to figure out the output buffer minimum size
    status = DeviceIoControl(handle, ioctl_code, BUFFER_BASE, 0x1000, BUFFER_BASE, 0)
    if status == 0xC0000023L: # STATUS_BUFFER_TOO_SMALL
        size = 0
        while status == 0xC0000023L and size < 0x1000:
            size += 2
            status = DeviceIoControl(handle, ioctl_code, BUFFER_BASE, 0x1000, BUFFER_BASE, size)
        print('  Guesstimate of minimal output buffer size: %d bytes' % size)
    else:
        print('  Output buffer size probe returned %08X' % status)

# See: https://msdn.microsoft.com/en-us/library/cc704588.aspx
__failed_status_codes = (
        0xC0000002L, # STATUS_NOT_IMPLEMENTED
        0xC0000010L, # STATUS_INVALID_DEVICE_REQUEST
        0xC00000BBL, # STATUS_NOT_SUPPORTED
    )

def scan_validate_status(status):
    "Check the status code for 'not implemented' IOCTLs"

    return status not in __failed_status_codes

def scan_functions(handle, device_type, req_access, transfer_type, ioctls):
    "Sweep-scan the `Function Code` field"

    # This is constant.
    ioctl_template = (device_type << 16) | (req_access << 14) | 0 | (transfer_type)

    func_code = 0
    while func_code <= 0xFFFL:
        ioctl_code = ioctl_template | (func_code << 2)
        # TODO: Some drivers return STATUS_NOT_IMPLEMENTED for incorrect params.
        status = DeviceIoControl(handle, ioctl_code, None, 0, None, 0)
        if scan_validate_status(status):
            print('IOCTL %08X: Returned NTSTATUS: %08X' % (ioctl_code, status))
            print('  DeviceType:%04X ReqAcc:%d FunctionCode:%03X XferType:%d' % (device_type, req_access, func_code, transfer_type))
            scan_ioctl(handle, ioctl_code)
            ioctls.append(ioctl_code)
        func_code += 1

def scan_device_type(handle, device_type, ioctls):
    "Sweep-scan the given `Device Type` for valid IOCTLs"

    print('Scanning device type %04X...' % device_type)
    access_type = 0
    while access_type < 3: # 3 is not used
        scan_functions(handle, device_type, access_type, 0, ioctls)
        scan_functions(handle, device_type, access_type, 1, ioctls)
        scan_functions(handle, device_type, access_type, 2, ioctls)
        scan_functions(handle, device_type, access_type, 3, ioctls)
        access_type += 1

def scan_device_type_range(handle, device_start, device_end, ioctls):
    "Scan the specified `Device Type` range"

    device_type = device_start
    while device_type <= device_end:
        scan_device_type(handle, device_type, ioctls)
        device_type += 1

def do_scan(args):
    "Main scanning function"

    handle = OpenFile(args.device_path, FILE_GENERIC_READ|FILE_GENERIC_WRITE)
    ioctls = []
    if args.scan_device is None:
        device_type_low = 0x0000
        device_type_high = 0xFFFF
        if args.scan_system:
            device_type_high = 0x7FFF
        if args.scan_vendor:
            device_type_low = 0x8000
        if device_type_low <= device_type_high:
            print('Scanning device type range %04X:%04X' % (device_type_low, device_type_high))
            scan_device_type_range(handle, device_type_low, device_type_high, ioctls)
        else:
            print('Incorrect scan range.')
    else:
        scan_device_type(handle, args.scan_device, ioctls)
    print('Scan completed (%d IOCTL codes reported).' % len(ioctls))
    NtClose(handle)
    return ioctls

#
# FUZZING (GENERATION/RECORDING)
#

def fuzz_generate(input_length):
    "Generate the data passed to the ioctl"

    nasty_bytes = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF)
    
    for offset in xrange(input_length):
        if random.random() <= 0.2:
            buffer_ptr[offset] = random.choice(nasty_bytes)
        offset += 1

def fuzz_ioctl(handle, ioctl_code, buffer_limits, record=False):
    "Perform one fuzzing interation over the given ioctl"

    # Initial conditions
    input_ptr, input_length, output_ptr, output_length = 0, 0, 0, 0

    transfer_type = ioctl_code & 3

    # Non-default input pointer?
    if buffer_limits[0][0] > 0 or random.random() < 0.5:
        input_ptr = BUFFER_BASE

        ctypes.memset(input_ptr, 0, 0x1000)
        input_length = random.randint(buffer_limits[0][0], buffer_limits[0][1])
        fuzz_generate(input_length)

    # Non-default output length?
    if buffer_limits[1][0] > 0 or random.random() < 0.5:
        output_length = random.randint(buffer_limits[1][0], buffer_limits[1][1])

    # Non-default output pointer?
    if buffer_limits[1][0] > 0 or random.random() < 0.5:
        # NOTE: For BUFFERED transfer, there is no point in providing an invalid pointer.
        if transfer_type == METHOD_BUFFERED or random.random() < 0.5:
            output_ptr = BUFFER_BASE
        else:
            output_ptr = 0xDEAD0000

    if record:
        replay_store(ioctl_code, input_ptr, input_length, output_ptr, output_length)

    # Execute
    status = DeviceIoControl(handle, ioctl_code, input_ptr, input_length, output_ptr, output_length)

def do_fuzz(args):
    "Main fuzzing function"

    # NOTE: not all access rights may be required -- adjust as needed.
    handle = OpenFile(args.device_path, FILE_GENERIC_READ|FILE_GENERIC_WRITE)

    # Limit input and output buffer sizes.
    buffer_limits = ((args.min_input, args.max_input), (args.min_output, args.max_output))

    # Loop forever.
    counter = 0
    counter2 = 0
    while True:
        fuzz_ioctl(handle, args.ioctl, buffer_limits, args.record)
        counter += 1
        if counter == 1000:
            sys.stdout.write('.')
            counter = 0
            counter2 += 1
            SetConsoleTitle('Fuzzing: iterations: %dk' % (counter2))
    NtClose(handle)

#
# FUZZING (REPLAYING)
#

def replay_store(ioctl_code, input_ptr, input_length, output_ptr, output_length):
    offset = 0
    b = []
    while offset < input_length:
        b.append('%d' % buffer_ptr[offset])
        offset += 1
    s = "(0x%08XL, 0x%08XL, 0x%08XL, 0x%08XL, 0x%08XL, [%s])\n" % (ioctl_code, input_ptr, input_length, output_ptr, output_length, ', '.join(b))
    with open('replay.dump', 'a') as fp:
        fp.write(s)
        # Force cache cleaning so if the crap crashes, we have the data on disk already
        fp.flush()
        os.fsync(fp.fileno())

def do_replay(args):
    handle = OpenFile(args.device_path, FILE_GENERIC_READ|FILE_GENERIC_WRITE)

    fp = open('replay.dump', 'r')
    lineno = 1
    while lineno < args.start:
        fp.readline()
        lineno += 1
    while lineno <= args.end:
        line = fp.readline()
        if not line:
            break
        ioctl_code, input_ptr, input_length, output_ptr, output_length, b = eval(line) # Ugh...
        ctypes.memset(buffer_ptr, 0, 0x1000)
        offset = 0
        while offset < input_length:
            buffer_ptr[offset] = b[offset]
            offset += 1
        print('Replaying call #%d...' % lineno)
        status = DeviceIoControl(handle, ioctl_code, input_ptr, input_length, output_ptr, output_length)
        print('IOCTL result: %08X' % status)
        lineno += 1
    NtClose(handle)

#
# TOP-LEVEL TASKS
#

def auto_int(x):
    return int(x, 0)
def hex_int(x):
    return int(x, 16)
def hex_long(x):
    return long(x, 16)

def main():
    parser = argparse.ArgumentParser(description='dumb IOCTL fuzzer')
    subparsers = parser.add_subparsers(help='action to perform')

    scan_parser = subparsers.add_parser('scan', help='scan a device for valid IOCTLs')
    scan_parser.add_argument('device_path',
        help='path to the device to fuzz')
    scan_parser.add_argument('--scan-device',
        help='only scan the specified device type (in hex)',
        metavar='DEVICE_TYPE',
        type=hex_int,
        default=None)
    scan_parser.add_argument('--scan-system',
        help='only scan for IOCTL device types 0000:7FFF',
        default=False,
        action='store_true')
    scan_parser.add_argument('--scan-vendor',
        help='only scan for IOCTL device types 8000:FFFF',
        default=False,
        action='store_true')
    scan_parser.set_defaults(handler=do_scan)

    fuzz_parser = subparsers.add_parser('fuzz', help='fuzz a specified IOCTL')
    fuzz_parser.add_argument('device_path',
        help='path to the device to fuzz')
    fuzz_parser.add_argument('ioctl',
        help='the IOCTL to fuzz (in hex)',
        type=hex_long)
    fuzz_parser.add_argument('--min-input',
        help='minimum input buffer length',
        metavar='SIZE',
        type=auto_int,
        default=0x00)
    fuzz_parser.add_argument('--max-input',
        help='maximum input buffer length',
        metavar='SIZE',
        type=auto_int,
        default=0x100)
    fuzz_parser.add_argument('--min-output',
        help='minimum output buffer length',
        metavar='SIZE',
        type=auto_int,
        default=0x00)
    fuzz_parser.add_argument('--max-output',
        help='maximum output buffer length',
        metavar='SIZE',
        type=auto_int,
        default=0x100)
    fuzz_parser.add_argument('--record',
        help='record all IOCTL traffic',
        default=False,
        action='store_true')
    fuzz_parser.set_defaults(handler=do_fuzz)

    replay_parser = subparsers.add_parser('replay', help='replay a recorded sequence')
    replay_parser.add_argument('device_path',
        help='path to the device to fuzz')
    replay_parser.add_argument('--start',
        help='which record to start from',
        metavar='OFFSET',
        type=int,
        default=0)
    replay_parser.add_argument('--end',
        help='which record to end with',
        metavar='OFFSET',
        type=int,
        default=2147483647)
    replay_parser.set_defaults(handler=do_replay)

    args = parser.parse_args()
    #print vars(args)

    # Handle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
    status = NtAllocateVirtualMemory(-1, ctypes.byref(ctypes.c_int(BUFFER_BASE)), 0, ctypes.byref(ctypes.c_int(0x1000)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if status < 0:
        print('NtAllocateVirtualMemory() failed with %08X' % to_unsigned(status))
        sys.exit(1)
    # TODO: Technically, there is absolutely no need to allocate a buffer this way...

    start_time = time.clock()
    try:
        args.handler(args)
    except KeyboardInterrupt:
        print('Interrupted.')
    wasted_time = time.clock() - start_time
    print('Time spent: %.2fs' % wasted_time)

    print('Exiting.')

if __name__ == "__main__":
    main()
