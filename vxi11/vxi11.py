"""Python VXI-11 driver

Copyright (c) 2012-2016 Alex Forencich and Michael Walle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from timeit import default_timer as time
from functools import wraps
from . import rpc
import random
import re

# VXI-11 RPC constants

# Device async
DEVICE_ASYNC_PROG = 0x0607b0
DEVICE_ASYNC_VERS = 1
DEVICE_ABORT = 1

# Device core
DEVICE_CORE_PROG = 0x0607af
DEVICE_CORE_VERS = 1
CREATE_LINK = 10
DEVICE_WRITE = 11
DEVICE_READ = 12
DEVICE_READSTB = 13
DEVICE_TRIGGER = 14
DEVICE_CLEAR = 15
DEVICE_REMOTE = 16
DEVICE_LOCAL = 17
DEVICE_LOCK = 18
DEVICE_UNLOCK = 19
DEVICE_ENABLE_SRQ = 20
DEVICE_DOCMD = 22
DESTROY_LINK = 23
CREATE_INTR_CHAN = 25
DESTROY_INTR_CHAN = 26

# Device intr
DEVICE_INTR_PROG = 0x0607b1
DEVICE_INTR_VERS = 1
DEVICE_INTR_SRQ = 30

# Error states
ERR_NO_ERROR = 0
ERR_SYNTAX_ERROR = 1
ERR_DEVICE_NOT_ACCESSIBLE = 3
ERR_INVALID_LINK_IDENTIFIER = 4
ERR_PARAMETER_ERROR = 5
ERR_CHANNEL_NOT_ESTABLISHED = 6
ERR_OPERATION_NOT_SUPPORTED = 8
ERR_OUT_OF_RESOURCES = 9
ERR_DEVICE_LOCKED_BY_ANOTHER_LINK = 11
ERR_NO_LOCK_HELD_BY_THIS_LINK = 12
ERR_IO_TIMEOUT = 15
ERR_IO_ERROR = 17
ERR_INVALID_ADDRESS = 21
ERR_ABORT = 23
ERR_CHANNEL_ALREADY_ESTABLISHED = 29

# Flags
OP_FLAG_WAIT_BLOCK = 1
OP_FLAG_END = 8
OP_FLAG_TERMCHAR_SET = 128

RX_REQCNT = 1
RX_CHR = 2
RX_END = 4


def parse_visa_resource_string(resource_string):
    # valid resource strings:
    # TCPIP::10.0.0.1::INSTR
    # TCPIP0::10.0.0.1::INSTR
    # TCPIP::10.0.0.1::gpib,5::INSTR
    # TCPIP0::10.0.0.1::gpib,5::INSTR
    # TCPIP0::10.0.0.1::usb0::INSTR
    # TCPIP0::10.0.0.1::usb0[1234::5678::MYSERIAL::0]::INSTR
    m = re.match('^(?P<prefix>(?P<type>TCPIP)\d*)(::(?P<arg1>[^\s:]+))'
                 '(::(?P<arg2>[^\s:]+(\[.+\])?))?(::(?P<suffix>INSTR))$',
                 resource_string, re.I)

    if m is not None:
        return dict(
            type=m.group('type').upper(),
            prefix=m.group('prefix'),
            arg1=m.group('arg1'),
            arg2=m.group('arg2'),
            suffix=m.group('suffix'))


# Exceptions
class Vxi11Exception(Exception):
    em = {0:  "No error",
          1:  "Syntax error",
          3:  "Device not accessible",
          4:  "Invalid link identifier",
          5:  "Parameter error",
          6:  "Channel not established",
          8:  "Operation not supported",
          9:  "Out of resources",
          11: "Device locked by another link",
          12: "No lock held by this link",
          15: "IO timeout",
          17: "IO error",
          21: "Invalid address",
          23: "Abort",
          29: "Channel already established"}

    def __init__(self, err=None, note=None):
        self.err = err
        self.note = note
        self.msg = ''

        if err is None:
            self.msg = note
        else:
            if type(err) is int:
                if err in self.em:
                    self.msg = "%d: %s" % (err, self.em[err])
                else:
                    self.msg = "%d: Unknown error" % err
            else:
                self.msg = err
            if note is not None:
                self.msg = "%s [%s]" % (self.msg, note)

    def __str__(self):
        return self.msg


class Packer(rpc.Packer):
    def pack_device_link(self, link):
        self.pack_int(link)

    def pack_create_link_parms(self, params):
        id, lock_device, lock_timeout, device = params
        self.pack_int(id)
        self.pack_bool(lock_device)
        self.pack_uint(lock_timeout)
        self.pack_string(device)

    def pack_device_write_parms(self, params):
        link, timeout, lock_timeout, flags, data = params
        self.pack_int(link)
        self.pack_uint(timeout)
        self.pack_uint(lock_timeout)
        self.pack_int(flags)
        self.pack_opaque(data)

    def pack_device_read_parms(self, params):
        link, request_size, timeout, lock_timeout, flags, term_char = params
        self.pack_int(link)
        self.pack_uint(request_size)
        self.pack_uint(timeout)
        self.pack_uint(lock_timeout)
        self.pack_int(flags)
        self.pack_int(term_char)

    def pack_device_generic_parms(self, params):
        link, flags, lock_timeout, timeout = params
        self.pack_int(link)
        self.pack_int(flags)
        self.pack_uint(lock_timeout)
        self.pack_uint(timeout)

    def pack_device_remote_func_parms(self, params):
        host_addr, host_port, prog_num, prog_vers, prog_family = params
        self.pack_uint(host_addr)
        self.pack_uint(host_port)
        self.pack_uint(prog_num)
        self.pack_uint(prog_vers)
        self.pack_int(prog_family)

    def pack_device_enable_srq_parms(self, params):
        link, enable, handle = params
        self.pack_int(link)
        self.pack_bool(enable)
        if len(handle) > 40:
            raise Vxi11Exception("array length too long")
        self.pack_opaque(handle)

    def pack_device_lock_parms(self, params):
        link, flags, lock_timeout = params
        self.pack_int(link)
        self.pack_int(flags)
        self.pack_uint(lock_timeout)

    def pack_device_docmd_parms(self, params):
        link, flags, timeout, lock_timeout, cmd, \
            network_order, datasize, data_in = params
        self.pack_int(link)
        self.pack_int(flags)
        self.pack_uint(timeout)
        self.pack_uint(lock_timeout)
        self.pack_int(cmd)
        self.pack_bool(network_order)
        self.pack_int(datasize)
        self.pack_opaque(data_in)

    def pack_device_error(self, error):
        self.pack_int(error)

    def pack_device_srq_parms(self, params):
        handle = params
        self.pack_opaque(handle)

    def pack_create_link_resp(self, params):
        error, link, abort_port, max_recv_size = params
        self.pack_int(error)
        self.pack_int(link)
        self.pack_uint(abort_port)
        self.pack_uint(max_recv_size)

    def pack_device_write_resp(self, params):
        error, size = params
        self.pack_int(error)
        self.pack_uint(size)

    def pack_device_read_resp(self, params):
        error, reason, data = params
        self.pack_int(error)
        self.pack_int(reason)
        self.pack_opaque(data)

    def pack_device_read_stb_resp(self, params):
        error, stb = params
        self.pack_int(error)
        self.pack_uint(stb)

    def pack_device_docmd_resp(self, params):
        error, data_out = params
        self.pack_int(error)
        self.pack_opaque(data_out)


class Unpacker(rpc.Unpacker):
    def unpack_device_link(self):
        return self.unpack_int()

    def unpack_create_link_parms(self):
        id = self.unpack_int()
        lock_device = self.unpack_bool()
        lock_timeout = self.unpack_uint()
        device = self.unpack_string()
        return id, lock_device, lock_timeout, device

    def unpack_device_write_parms(self):
        link = self.unpack_int()
        timeout = self.unpack_uint()
        lock_timeout = self.unpack_uint()
        flags = self.unpack_int()
        data = self.unpack_opaque()
        return link, timeout, lock_timeout, flags, data

    def unpack_device_read_parms(self):
        link = self.unpack_int()
        request_size = self.unpack_uint()
        timeout = self.unpack_uint()
        lock_timeout = self.unpack_uint()
        flags = self.unpack_int()
        term_char = self.unpack_int()
        return link, request_size, timeout, lock_timeout, flags, term_char

    def unpack_device_generic_parms(self):
        link = self.unpack_int()
        flags = self.unpack_int()
        lock_timeout = self.unpack_uint()
        timeout = self.unpack_uint()
        return link, flags, lock_timeout, timeout

    def unpack_device_remote_func_parms(self):
        host_addr = self.unpack_uint()
        host_port = self.unpack_uint()
        prog_num = self.unpack_uint()
        prog_vers = self.unpack_uint()
        prog_family = self.unpack_int()
        return host_addr, host_port, prog_num, prog_vers, prog_family

    def unpack_device_enable_srq_parms(self):
        link = self.unpack_int()
        enable = self.unpack_bool()
        handle = self.unpack_opaque()
        return link, enable, handle

    def unpack_device_lock_parms(self):
        link = self.unpack_int()
        flags = self.unpack_int()
        lock_timeout = self.unpack_uint()
        return link, flags, lock_timeout

    def unpack_device_docmd_parms(self):
        link = self.unpack_int()
        flags = self.unpack_int()
        timeout = self.unpack_uint()
        lock_timeout = self.unpack_uint()
        cmd = self.unpack_int()
        network_order = self.unpack_bool()
        datasize = self.unpack_int()
        data_in = self.unpack_opaque()
        return (link, flags, timeout, lock_timeout, cmd,
                network_order, datasize, data_in)

    def unpack_device_error(self):
        return self.unpack_int()

    def unpack_device_srq_params(self):
        handle = self.unpack_opaque()
        return handle

    def unpack_create_link_resp(self):
        error = self.unpack_int()
        link = self.unpack_int()
        abort_port = self.unpack_uint()
        max_recv_size = self.unpack_uint()
        return error, link, abort_port, max_recv_size

    def unpack_device_write_resp(self):
        error = self.unpack_int()
        size = self.unpack_uint()
        return error, size

    def unpack_device_read_resp(self):
        error = self.unpack_int()
        reason = self.unpack_int()
        data = self.unpack_opaque()
        return error, reason, data

    def unpack_device_read_stb_resp(self):
        error = self.unpack_int()
        stb = self.unpack_uint()
        return error, stb

    def unpack_device_docmd_resp(self):
        error = self.unpack_int()
        data_out = self.unpack_opaque()
        return error, data_out

    def done(self):
        # ignore any trailing bytes
        pass


class CoreClient(rpc.TCPClient):

    def __init__(self, host, port=0, timeout=None):
        self.packer = Packer()
        self.unpacker = Unpacker('')
        rpc.TCPClient.__init__(self, host, DEVICE_CORE_PROG, DEVICE_CORE_VERS,
                               port=port, timeout=timeout)

    def create_link(self, id, lock_device, lock_timeout, name):
        params = (id, lock_device, lock_timeout, name)
        return self.make_call(CREATE_LINK, params,
                              self.packer.pack_create_link_parms,
                              self.unpacker.unpack_create_link_resp)

    def device_write(self, link, timeout, lock_timeout, flags, data):
        params = (link, timeout, lock_timeout, flags, data)
        return self.make_call(DEVICE_WRITE, params,
                              self.packer.pack_device_write_parms,
                              self.unpacker.unpack_device_write_resp)

    def device_read(self, link, request_size, timeout, lock_timeout, flags,
                    term_char):
        params = (link, request_size, timeout, lock_timeout, flags, term_char)
        return self.make_call(DEVICE_READ, params,
                              self.packer.pack_device_read_parms,
                              self.unpacker.unpack_device_read_resp)

    def device_read_stb(self, link, flags, lock_timeout, timeout):
        params = (link, flags, lock_timeout, timeout)
        return self.make_call(DEVICE_READSTB, params,
                              self.packer.pack_device_generic_parms,
                              self.unpacker.unpack_device_read_stb_resp)

    def device_trigger(self, link, flags, lock_timeout, timeout):
        params = (link, flags, lock_timeout, timeout)
        return self.make_call(DEVICE_TRIGGER, params,
                              self.packer.pack_device_generic_parms,
                              self.unpacker.unpack_device_error)

    def device_clear(self, link, flags, lock_timeout, timeout):
        params = (link, flags, lock_timeout, timeout)
        return self.make_call(DEVICE_CLEAR, params,
                              self.packer.pack_device_generic_parms,
                              self.unpacker.unpack_device_error)

    def device_remote(self, link, flags, lock_timeout, timeout):
        params = (link, flags, lock_timeout, timeout)
        return self.make_call(DEVICE_REMOTE, params,
                              self.packer.pack_device_generic_parms,
                              self.unpacker.unpack_device_error)

    def device_local(self, link, flags, lock_timeout, timeout):
        params = (link, flags, lock_timeout, timeout)
        return self.make_call(DEVICE_LOCAL, params,
                              self.packer.pack_device_generic_parms,
                              self.unpacker.unpack_device_error)

    def device_lock(self, link, flags, lock_timeout):
        params = (link, flags, lock_timeout)
        return self.make_call(DEVICE_LOCK, params,
                              self.packer.pack_device_lock_parms,
                              self.unpacker.unpack_device_error)

    def device_unlock(self, link):
        return self.make_call(DEVICE_UNLOCK, link,
                              self.packer.pack_device_link,
                              self.unpacker.unpack_device_error)

    def device_enable_srq(self, link, enable, handle):
        params = (link, enable, handle)
        return self.make_call(DEVICE_ENABLE_SRQ, params,
                              self.packer.pack_device_enable_srq_parms,
                              self.unpacker.unpack_device_error)

    def device_docmd(self, link, flags, timeout, lock_timeout, cmd,
                     network_order, datasize, data_in):
        params = (link, flags, timeout, lock_timeout, cmd, network_order,
                  datasize, data_in)
        return self.make_call(DEVICE_DOCMD, params,
                              self.packer.pack_device_docmd_parms,
                              self.unpacker.unpack_device_docmd_resp)

    def destroy_link(self, link):
        return self.make_call(DESTROY_LINK, link,
                              self.packer.pack_device_link,
                              self.unpacker.unpack_device_error)

    def create_intr_chan(self, host_addr, host_port, prog_num, prog_vers,
                         prog_family):
        params = (host_addr, host_port, prog_num, prog_vers, prog_family)
        return self.make_call(CREATE_INTR_CHAN, params,
                              self.packer.pack_device_remote_func_parms,
                              self.unpacker.unpack_device_error)

    def destroy_intr_chan(self):
        return self.make_call(DESTROY_INTR_CHAN, None,
                              None,
                              self.unpacker.unpack_device_error)


class AbortClient(rpc.TCPClient):
    def __init__(self, host, port=0, timeout=None):
        self.packer = Packer()
        self.unpacker = Unpacker('')
        rpc.TCPClient.__init__(
            self, host, DEVICE_ASYNC_PROG, DEVICE_ASYNC_VERS,
            port=port, timeout=timeout)

    def device_abort(self, link):
        return self.make_call(DEVICE_ABORT, link,
                              self.packer.pack_device_link,
                              self.unpacker.unpack_device_error)


class Instrument(object):
    """VXI-11 instrument interface client.

    Args:
        name (str or None):               Name of the instrument
        cliend_id (int or None):          ID fot the client
        term_char (char or None):         A custom term character
        host (str):                       Host name of the intrument
        instrument_timeout (int):         Timeout in seconds for the instrument
        connection_timeout (int or None): Timeout in seconds for the socket
        callback_timeout (int or None):   Timeout in seconds to get callbacks
                                          while waiting for a response.
        callback (callable or None):      Called after every successful
                                          operation or callback timeout.

    If callback_timeout is None, no callback timeout will be raised.
    If callback is None, nothing is called.
    The callable should handle one argument. The exception is passed
    if a callback timeout has been raised, None otherwise.
    """

    def __init__(self, host,
                 name=None,
                 client_id=None,
                 term_char=None,
                 instrument_timeout=10000,
                 connection_timeout=None,
                 callback_timeout=None,
                 callback=None):
        """Create new VXI-11 instrument object"""
        # VISA resource string
        if host.upper().startswith('TCPIP') and '::' in host:
            res = parse_visa_resource_string(host)
            if res is None:
                raise Vxi11Exception('Invalid resource string', 'init')
            host = res['arg1']
            name = res['arg2']
        # Set arguments
        self.host = host
        self.callback = callback
        self.term_char = term_char
        self.name = name or "inst0"
        self.client_id = client_id or random.getrandbits(31)
        # Set timeout arguments
        self.connection_timeout = connection_timeout
        self.instrument_timeout = instrument_timeout
        self.callback_timeout = instrument_timeout
        if callback_timeout:
            self.callback_timeout = callback_timeout
        # Internal timeouts
        self.timeout_ms = int(self.callback_timeout * 1000)
        self.lock_timeout_ms = int(self.callback_timeout * 1000)
        # Initialize
        self.link = None
        self.client = None
        self.abort_client = None
        self.max_recv_size = 0
        # Connect to the client
        self.client = CoreClient(self.host, self.connection_timeout)

    def __del__(self):
        self.close()

    # Open/close commands

    def open(self):
        """Open connection to VXI-11 instrument"""
        # Already open
        if self.link is not None:
            return
        # Initialize client
        if not self.client:
            self.client = CoreClient(self.host, self.connection_timeout)
        # Create link
        error, link, abort_port, max_recv_size = self.client.create_link(
            self.client_id, 0, self.lock_timeout_ms, self.name.encode("utf-8"))
        # Raise error
        if error:
            raise Vxi11Exception(error, 'open')
        # Initialize abort client
        self.abort_client = AbortClient(self.host, abort_port)
        # Save the link
        self.link = link
        self.max_recv_size = min(max_recv_size, 1073741824)

    def close(self, destroy_link=True):
        """Close connection"""
        # Connection already closed
        if self.client is None:
            return
        try:
            # Destroy the link if necessary
            if destroy_link and self.link is not None:
                self.client.destroy_link(self.link)
        finally:
            try:
                # Make sure the client is closed
                self.client.close()
            finally:
                # Make sure we clean the state
                self.link = None
                self.client = None

    # High level methods

    def ask_raw(self, data, num=-1):
        """Write then read binary data"""
        self.write_raw(data)
        return self.read_raw(num)

    def write(self, message, encoding='utf-8'):
        """Write string to instrument"""
        if isinstance(message, basestring):
            self.write_raw(str(message).encode(encoding))
            return
        # Recursive call
        for command in message:
            self.write(command, encoding)

    def read(self, num=-1, encoding='utf-8'):
        """Read string from instrument"""
        return self.read_raw(num).decode(encoding).rstrip('\r\n')

    def ask(self, message, num=-1, encoding='utf-8'):
        """Write then read string"""
        if isinstance(message, basestring):
            self.write(message, encoding)
            return self.read(num, encoding)
        # Recursive call
        return [self.ask(command, num, encoding) for command in message]

    # Base command decorator

    def base_command(func):
        """Decorator to handle instrument timeout."""
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Open link
            if self.link is None:
                self.open()
            # Init time
            start = time()
            no_control = self.callback_timeout >= self.instrument_timeout
            # Loop over timeouts
            while True:
                try:
                    # Run the function
                    result = func(self, *args, **kwargs)
                except Vxi11Exception as exc:
                    # Time control
                    no_timeout = exc.err != ERR_IO_TIMEOUT
                    expired = time() > start + self.instrument_timeout
                    # Reraise exception
                    if no_control or no_timeout or expired:
                        raise
                    # Callback with exc
                    if self.callback:
                        self.callback(exc)
                else:
                    # Callback without exc
                    if self.callback:
                        self.callback(None)
                    # Return
                    return result
        # Decorate
        return wrapper

    # Base commands

    @base_command
    def read_raw(self, num=-1):
        """Read binary data from instrument"""
        # Initialize
        flags, reason, read_data = 0, 0, b''
        read_length = self.max_recv_size
        # Get terminator
        term_char = 0
        if self.term_char is not None:
            flags = OP_FLAG_TERMCHAR_SET
            term_char = str(self.term_char).encode('utf-8')[0]
        # Loop over read requests
        while reason & (RX_END | RX_CHR) == 0:
            # Get read length
            if 0 < num < read_length:
                read_length = num
            # Read request
            error, reason, data = self.client.device_read(
                self.link, read_length, self.timeout_ms, self.lock_timeout_ms,
                flags, term_char)
            # Raise error
            if error:
                raise Vxi11Exception(error, 'read')
            # Concatenate result
            read_data.extend(data)
            # Break if enough data
            if 0 < num <= len(data):
                break
            # Update remaining bytes to read
            num -= len(data)
        # Return result
        return bytes(read_data)

    @base_command
    def write_raw(self, data):
        """Write binary data to instrument"""
        # Initialize
        flags, chunk = 0, self.max_recv_size
        # Append terminator
        if self.term_char is not None:
            flags = OP_FLAG_TERMCHAR_SET
            term_char = str(self.term_char).encode('utf-8')[0]
            data += term_char
        # Loop over write requests
        offsets = range(0, len(data), chunk)
        for offset in offsets:
            # Get block
            if offset == offsets[-1]:
                flags |= OP_FLAG_END
            block = data[offset:offset+chunk]
            # Write request
            error, size = self.client.device_write(
                self.link, self.timeout_ms, self.lock_timeout_ms, flags, block)
            # Raise error
            if error:
                raise Vxi11Exception(error, 'write')
            elif size < len(block):
                raise Vxi11Exception("did not write complete block", 'write')

    @base_command
    def read_stb(self):
        """Read status byte command"""
        flags = 0
        error, stb = self.client.device_read_stb(
            self.link, flags, self.lock_timeout_ms, self.timeout_ms)
        if error:
            raise Vxi11Exception(error, 'read_stb')
        return stb

    @base_command
    def trigger(self):
        """Send trigger command"""
        flags = 0
        error = self.client.device_trigger(
            self.link, flags, self.lock_timeout_ms, self.timeout_ms)
        if error:
            raise Vxi11Exception(error, 'trigger')

    @base_command
    def clear(self):
        """Send clear command"""
        flags = 0
        error = self.client.device_clear(
            self.link, flags, self.lock_timeout_ms, self.timeout_ms)
        if error:
            raise Vxi11Exception(error, 'clear')

    @base_command
    def remote(self):
        """Send remote command"""
        flags = 0
        error = self.client.device_remote(
            self.link, flags, self.lock_timeout_ms, self.timeout_ms)
        if error:
            raise Vxi11Exception(error, 'remote')

    @base_command
    def local(self):
        """Send local command"""
        flags = 0
        error = self.client.device_local(
            self.link, flags, self.lock_timeout_ms, self.timeout_ms)
        if error:
            raise Vxi11Exception(error, 'local')

    @base_command
    def lock(self):
        """Send lock command"""
        flags = 0
        error = self.client.device_lock(self.link, flags, self.lock_timeout_ms)
        if error:
            raise Vxi11Exception(error, 'lock')

    @base_command
    def unlock(self):
        """Send unlock command"""
        error = self.client.device_unlock(self.link)
        if error:
            raise Vxi11Exception(error, 'unlock')

    @base_command
    def abort(self):
        """Asynchronous abort command"""
        error = self.abort_client.device_abort(self.link)
        if error:
            raise Vxi11Exception(error, 'abort')
