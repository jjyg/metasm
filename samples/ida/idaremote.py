import idautils
import idaapi
import idc

import socket
import select

# remote control for IDA using a text protocol
# by default listens on localhost:56789
# tested with IDA7.3, IDA7.4
# to stop, run 'idaremote.quit()' from within IDA

class IdaRemote:
    sock = None
    sock_client = None
    ida_timer_delay = 50
    debug = False

    # open a network socket for incoming connections
    def listen(self, host="localhost", port=56789):
        idaapi.msg("IdaRemote listening on {}:{}\n".format(host, str(port)))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(10)

    # register in ida to call main_iter() every 50ms
    # allows to runs in the IDA main loop (modifying the IDB from a thread may corrupt the IDB)
    def register_ida_timer(self, delay=50):
        self.ida_timer_delay = delay
        ida_kernwin.register_timer(delay, self.main_iter)

    # check if we have a pending connection, handle it
    def main_iter(self):
        if not self.sock:
            # cli called cmd_exitplugin(), unregister the timer
            return -1

        r, w, e = select.select([self.sock], [], [], 0)
        for s in r:
            client, addr = s.accept()
            select.select([client], [], [], 10)
            self.sock_client = client
            rq = self.client_recv(4096)
            ans = self.handle_rq(rq)
            self.client_send(ans)
            client.close()
            self.sock_client = None

        return self.ida_timer_delay

    # parse one request, handle it, return the reply
    def handle_rq(self, rq):
        if self.debug:
            if len(rq) > 64:
                idaapi.msg("IdaRemote request: {}...\n".format(repr(rq[:62])))
            else:
                idaapi.msg("IdaRemote request: {}\n".format(repr(rq)))
        splt = rq.split(" ", 1)
        cmd = splt[0]
        method = getattr(self, "cmd_" + cmd, False)
        if method:
            try:
                # introspection to find the required number of args
                # avoids parsing quoted strings in the queries, allow some methods to receive args containing space characters (eg set_comment)
                method_nargs = method.__code__.co_argcount - 1
                if method_nargs == 0:
                    return method()
                elif method_nargs == 1:
                    return method(splt[1])
                else:
                    return method(*splt[1].split(" ", method_nargs-1))
            except Exception as err:
                idaapi.msg("IdaRemote exception: {}\n".format(err))
                return ""
        else:
            return "unknown command " + cmd

    def client_send(self, msg):
        # python2+3 compat
        try:
            bmsg = bytes(msg, 'latin1')
        except:
            bmsg = bytes(msg)
        try:
            return self.sock_client.send(bmsg)
        except Exception as err:
            idaapi.msg("IdaRemote client_send(): {}\n".format(err))
            return 0

    def client_recv(self, ln):
        bmsg = self.sock_client.recv(ln)
        # python2+3 compat # lol
        msg = str(bmsg.decode('latin1'))
        return msg

    def client_wait(self, time_s):
        return select.select([self.sock_client], [], [], time_s)

    # hexencode a buffer
    def str2hex(self, raw):
        # python2+3 compat
        try:
            # raw already bytes
            return "".join(["{:02X}".format(b) for b in raw])
        except:
            try:
                # python3, raw is string
                return "".join(["{:02X}".format(b) for b in bytes(raw, 'latin1')])
            except:
                # python2
                return "".join(["{:02X}".format(ord(b)) for b in bytes(raw)])

    # encode an address in hex, return '-1' for invalid address
    def fmt_addr(self, addr):
        if addr == ida_idaapi.BADADDR:
            return "-1"
        else:
            return "0x{:04X}".format(addr)

    def quit(self):
        self.cmd_exitplugin()
        return ""


    # list of supported commands

    # address -> label name
    def cmd_get_label(self, addr):
        return idc.get_name(int(addr, 0))

    # set a label at an address
    def cmd_set_label(self, addr, label):
        if idaapi.set_name(int(addr, 0), label, idaapi.SN_NOWARN|idaapi.SN_NOCHECK):
            return "ok"
        return ""

    # label name -> address
    # return 0xffffffff or 0xffffffffffffffff (BAD_ADDR) if not existing
    def cmd_resolve_label(self, label):
        addr = idc.get_name_ea_simple(label)
        return self.fmt_addr(addr)

    # return the list of addrs for which a name exists
    def cmd_get_named_addrs(self, a_start, a_end):
        # idautils.Names() does not work in 7.3
        return " ".join([self.fmt_addr(a) for a in range(int(a_start, 0), int(a_end, 0)) if idc.get_name(a)])

    # read raw data from an address
    def cmd_get_bytes(self, addr, len):
        raw = idc.get_bytes(int(addr, 0), int(len, 0))
        if raw:
            return self.str2hex(raw)
        return ""

    # read one byte
    def cmd_get_byte(self, addr):
        return str(idc.get_wide_byte(int(addr, 0)))

    # read one word
    def cmd_get_word(self, addr):
        return str(idc.get_wide_word(int(addr, 0)))

    # read one dword
    def cmd_get_dword(self, addr):
        return str(idc.get_wide_dword(int(addr, 0)))

    # read one qword
    def cmd_get_qword(self, addr):
        return str(idc.get_qword(int(addr, 0)))

    # return an array of xrefs to the specified addr
    # array is a sequence of hex addresses separate by spaces
    def cmd_get_xrefs_to(self, addr):
        ALL_XREFS = 0
        xrefs = idautils.XrefsTo(int(addr, 0), ALL_XREFS)
        return " ".join([self.fmt_addr(xr.frm) for xr in xrefs])

    # end the idaremote plugin loop, close the listening socket
    def cmd_exitplugin(self):
        idaapi.msg("IdaRemote closing\n")
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ida_timer_delay = -1
        return "bye"

    # ask IDA to save IDB and exit
    def cmd_exit_ida(self, c):
        idaapi.msg("IdaRemote exiting IDA\n")
        idc.qexit(int(c, 0))
        return "bye"    # not reached?

    # get the non-repeatable comment at address
    def cmd_get_comment(self, addr):
        c = idc.get_cmt(int(addr, 0), 0)
        if c:
            return c
        return ""

    # set the non-repeatable comment at address
    def cmd_set_comment(self, addr, cmt):
        if idc.set_cmt(int(addr, 0), cmt, 0):
            return "ok"
        return ""

    # return the current cursor address (ScreenEA)
    def cmd_get_cursor_pos(self):
        return self.fmt_addr(idc.get_screen_ea())

    # set the current cursor address
    def cmd_set_cursor_pos(self, a):
        if idc.jumpto(int(a, 0)):
            return "ok"
        return ""

    # return the start/end address of the current selection
    def cmd_get_selection(self):
        return " ".join(self.fmt_addr(a) for a in [idc.read_selection_start(), idc.read_selection_end()])

    # return the flags for an address
    def cmd_get_flags(self, a):
        return "0x{:08X}".format(idc.get_full_flags(int(a, 0)))

    # return the list of head addresses (instruction or data) in a range
    def cmd_get_heads(self, a_start, a_end):
        return " ".join([self.fmt_addr(a) for a in Heads(int(a_start, 0), int(a_end, 0))])

    # return the previous head before an address
    def cmd_get_prev_head(self, a):
        return self.fmt_addr(idc.prev_head(int(a, 0)))

    # return the next head after an address
    def cmd_get_next_head(self, a):
        return self.fmt_addr(idc.next_head(int(a, 0)))

    # return the size of an item (head)
    def cmd_get_item_size(self, a):
        return str(idc.get_item_size(int(a, 0)))

    # return the list of functions in a range
    def cmd_get_functions(self, a_start, a_end):
        return " ".join([self.fmt_addr(a) for a in Functions(int(a_start, 0), int(a_end, 0))])

    # return the address of a function from the address of an instruction
    def cmd_get_function_start(self, a):
        addr = idc.get_name_ea_simple(idc.get_func_name(int(a, 0)))
        return self.fmt_addr(addr)

    # return the name of a function from the address of an instruction of the body
    def cmd_get_function_name(self, a):
        return idc.get_func_name(int(a, 0))

    # return the (nonrepeatable) function comment
    def cmd_get_function_comment(self, a):
        return idc.get_func_cmt(int(a, 0), 0)

    # set the (nonrepeatable) function comment
    def cmd_set_function_comment(self, a, c):
        if idc.set_func_cmt(int(a, 0), c, 0):
            return "ok"
        return ""

    # return the function flags for an address
    def cmd_get_function_flags(self, a):
        return "0x{:08X}".format(idc.get_func_attr(int(a, 0), idc.FUNCATTR_FLAGS))

    # return the address of each basicblock of the function
    def cmd_get_function_blocks(self, a):
        fc = idaapi.FlowChart(idaapi.get_func(int(a, 0)))
        return " ".join([self.fmt_addr(b.start_ea) for b in fc])

    # return the C prototype for an address
    def cmd_get_type(self, a):
        t = idc.get_type(int(a, 0))
        if not t:
            t = ""
        return t

    # set the C prototype for an address
    def cmd_set_type(self, a, t):
        if idc.SetType(int(a, 0), t):
            return "ok"
        return ""

    # return list of all segments start address
    def cmd_get_segments(self):
        return " ".join([self.fmt_addr(a) for a in Segments()])

    # return the start address for the segment from any address within
    def cmd_get_segment_start(self, a):
        return self.fmt_addr(idc.get_segm_start(int(a, 0)))

    # return the end address for the segment starting at a
    def cmd_get_segment_end(self, a):
        return self.fmt_addr(idc.get_segm_end(int(a, 0)))

    # return the name of a segment
    def cmd_get_segment_name(self, a):
        return idc.get_segm_name(int(a, 0))

    # return the mnemonic of an opcode at addr
    def cmd_get_op_mnemonic(self, a):
        return idc.print_insn_mnem(int(a, 0))

    # tell IDA to convert an address into an alignment directive
    def cmd_make_align(self, a, count, align):
        return str(idc.create_align(int(a, 0), int(count, 0), int(align, 0)))

    # tell IDA to make an array, reuse current type
    def cmd_make_array(self, a, count):
        return str(idc.make_array(int(a, 0), int(count, 0)))

    # tell IDA to convert to a byte
    def cmd_make_byte(self, a):
        return str(idc.create_data(int(a, 0), idc.FF_BYTE, 1, ida_idaapi.BADADDR))

    # tell IDA to convert to a word
    def cmd_make_word(self, a):
        return str(idc.create_data(int(a, 0), idc.FF_WORD, 2, ida_idaapi.BADADDR))

    # tell IDA to convert to a dword
    def cmd_make_dword(self, a):
        return str(idc.create_data(int(a, 0), idc.FF_DWORD, 4, ida_idaapi.BADADDR))

    # tell IDA to convert to a qword
    def cmd_make_qword(self, a):
        return str(idc.create_data(int(a, 0), idc.FF_QWORD, 8, ida_idaapi.BADADDR))

    # tell IDA to convert to a string
    # a_end = 0 => auto size
    def cmd_make_string(self, a, len, kind):
        return str(ida_bytes.create_strlit(int(a, 0), int(len, 0), int(kind, 0)))

    # tell IDA to disassemble
    def cmd_make_code(self, a):
        return str(idc.create_insn(int(a, 0)))

    # undefine at an address
    # for code, undefine following instructions too
    def cmd_undefine(self, a):
        return str(idc.del_items(int(a, 0), 1))

    # patch a raw byte in the IDB
    def cmd_patch_byte(self, a, v):
        if idc.patch_byte(int(a, 0), int(v, 0)):
            return "ok"
        return ""

    # return the path of the analysed file
    def cmd_get_input_path(self):
        return idc.get_input_file_path()

    # return the nth entrypoint address
    def cmd_get_entry(self, idx):
        return self.fmt_addr(idc.get_entry(idc.get_entry_ordinal(int(idx, 0))))

    # return <cpu_name> <word size> <endianness>
    def cmd_get_cpuinfo(self):
        info = idaapi.get_inf_structure()
        cpu_name = info.procname
        if info.is_64bit():
            word_size = 64
        elif info.is_32bit():
            word_size = 32
        else:
            word_size = 16
        if info.is_be():
            endian = 'big'
        else:
            endian = 'little'
        return " ".join([cpu_name, str(word_size), endian])

    # identify the remote version
    # ex: "ida 7.4"
    def cmd_get_remoteid(self):
        return "ida " + ida_kernwin.get_kernel_version()

    # run many commands at once
    # batch is a list of separate commands
    # run all of them and return the array of results
    # array encoded as sequence of <str(int(len(element)))><space><element>
    # ex: "14 get_cursor_pos4 exitplugin" -> "4 0x423 bye"
    def cmd_batch(self, batch):
        ans_ary = []
        off = 0
        while off < len(batch):
            off_len = batch.find(" ", off)  # way faster than split() for large strings
            ln = int(batch[off:off_len])
            off = off_len+1+ln
            rq = batch[off_len+1:off]

            ans = self.handle_rq(rq)
            if not isinstance(ans, str):
                idaapi.msg("output of {} is not a str\n".format(rq))

            ans_ary.append(ans)

        return "".join([str(len(ans)) + " " + ans for ans in ans_ary])

    # handle multiple sequential requests/responses in the client socket
    # allow large requests
    # payload = <str(int(len(request0)))><space><request0>
    # sends back <str(int(len(answer0)))><space><answer0>
    # reads another request until len(request) == 0
    # if the 1st request is incomplete from the initial recv(), fetch missing data
    def cmd_multirq(self, buf):
        while 1:
            if not " " in buf:
                idaapi.msg("IdaRemote multirq client timeout\n")
                return ""

            ln, buf = buf.split(" ", 1)
            if int(ln) == 0:
                return "0 "

            while int(ln) > len(buf):
                buf += self.client_recv(int(ln)-len(buf))

            rq = buf[:int(ln)]
            buf = buf[int(ln):]

            ans = self.handle_rq(rq)

            self.client_send(str(len(ans)) + " " + ans)

            if " " not in buf:
                self.client_wait(4)
                buf += self.client_recv(4096)



idaremote = IdaRemote()
idaremote.listen()
idaremote.register_ida_timer()
