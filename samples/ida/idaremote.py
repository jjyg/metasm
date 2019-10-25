import idautils
import idaapi
import idc

import socket
import select

# remote control for IDA using a text protocol
# by default listens on localhost:56789
# tested with IDA7.3
# to stop, run 'idaremote.cmd_quit()' from within IDA

class IdaRemote:
    sock = None
    sock_client = None
    ida_timer_delay = 50

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
            # cli called cmd_quit(), unregister the timer
            return -1

        r, w, e = select.select([self.sock], [], [], 0)
        for s in r:
            client, addr = s.accept()
            select.select([client], [], [], 10)
            rq = client.recv(4096)
            self.sock_client = client
            ans = self.handle_rq(rq)
            if ans:
                client.send(ans)
            client.close()
            self.sock_client = None

        return self.ida_timer_delay

    # parse one request, handle it, return the reply
    def handle_rq(self, rq):
        splt = rq.split(" ", 1)
        cmd = splt[0]
        method = getattr(self, "cmd_" + cmd, False)
        if method:
            try:
                # introspection to find the required number of args
                # avoids parsing quoted strings in the queries, allow some methods to receive args containing space characters (eg set_comment)
                method_nargs = method.func_code.co_argcount - 1
                if method_nargs == 0:
                    return method()
                elif method_nargs == 1:
                    return method(splt[1])
                else:
                    return method(*splt[1].split(" ", method_nargs-1))
            except Exception as err:
                # TODO display call stack for debugging
                idaapi.msg("IdaRemote exception: {}\n".format(err))
                return ""
        else:
            return "unknown command " + cmd

    # hexencode a buffer
    def str2hex(self, raw):
        return "".join(["{:02X}".format(ord(b)) for b in bytes(raw)])


    # list of supported commands

    # address -> label name
    def cmd_get_label(self, addr):
        return idc.get_name(int(addr, 0))

    # set a label at an address
    def cmd_set_label(self, addr, label):
        idc.set_name(int(addr, 0), label)
        return ""

    # label name -> address
    # return 0xffffffff or 0xffffffffffffffff (BAD_ADDR) if not existing
    def cmd_resolve_label(self, label):
        addr = LocByName(label)
        return "0x{:08X}".format(addr)

    # return the list of addrs for which a name exists
    def cmd_get_named_addrs(self, a_start, a_end):
        # idautils.Names() does not work
        return " ".join(["0x{:X}".format(a) for a in range(int(a_start, 0), int(a_end, 0)) if idc.get_name(a)])

    # read raw data from an address
    def cmd_get_bytes(self, addr, len):
        raw = idc.get_bytes(int(addr, 0), int(len, 0))
        if raw:
            return self.str2hex(raw)
        else:
            return ""

    # read one byte
    def cmd_get_byte(self, addr):
        return str(Byte(int(addr, 0)))

    # read one word
    def cmd_get_word(self, addr):
        return str(Word(int(addr, 0)))

    # read one dword
    def cmd_get_dword(self, addr):
        return str(Dword(int(addr, 0)))

    # read one qword
    def cmd_get_qword(self, addr):
        return str(Qword(int(addr, 0)))

    # return an array of xrefs to the specified addr
    # array is a sequence of hex addresses separate by spaces
    def cmd_get_xrefs_to(self, addr):
        ALL_XREFS = 0
        xrefs = idautils.XrefsTo(int(addr, 0), ALL_XREFS)
        return " ".join(["0x{:08X}".format(xr.frm) for xr in xrefs])
        
    # end the idaremote plugin loop, close the listening socket
    def cmd_quit(self):
        idaapi.msg("IdaRemote closing\n")
        self.sock.close()
        self.sock = None
        self.ida_timer_delay = -1
        return "bye"

    # ask IDA to save IDB and exit
    def cmd_exit_ida(self, c):
        idaapi.msg("IdaRemote exiting IDA\n")
        Exit(int(c, 0))
        return "bye"    # not reached?

    # get the non-repeatable comment at address
    def cmd_get_comment(self, addr):
        return Comment(int(addr, 0))

    # set the non-repeatable comment at address
    def cmd_set_comment(self, addr, cmt):
        if MakeComm(int(addr, 0), cmt):
            return "ok"
        return "nope"

    # return the current cursor address (ScreenEA)
    def cmd_get_cursor_pos(self):
        return "0x{:08X}".format(ScreenEA())

    # set the current cursor address
    def cmd_set_cursor_pos(self, a):
        Jump(int(a, 0))
        return ""

    # return the start/end address of the current selection
    def cmd_get_selection(self):
        return "0x{:08X} 0x{:08X}".format(SelStart(), SelEnd())

    # return the flags for an address
    def cmd_get_flags(self, a):
        return "0x{:08X}".format(GetFlags(int(a, 0)))

    # return the list of head addresses (instruction or data) in a range
    def cmd_get_heads(self, a_start, a_end):
        return " ".join(["0x{:X}".format(a) for a in Heads(int(a_start, 0), int(a_end, 0))])

    # return the previous head before an address
    def cmd_get_prev_head(self, a):
        return "0x{:X}".format(PrevHead(int(a, 0)))

    # return the next head after an address
    def cmd_get_next_head(self, a):
        return "0x{:X}".format(NextHead(int(a, 0)))

    # return the list of functions in a range
    def cmd_get_functions(self, a_start, a_end):
        return " ".join(["0x{:X}".format(a) for a in Functions(int(a_start, 0), int(a_end, 0))])

    # return the name of a function from the address of an instruction of the body
    def cmd_get_function_name(self, a):
        return GetFunctionName(int(a, 0))

    # return the (nonrepeatable) function comment
    def cmd_get_function_comment(self, a):
        return GetFunctionCmt(int(a, 0), 0)

    # set the (nonrepeatable) function comment
    def cmd_set_function_comment(self, a, c):
        return SetFunctionCmt(int(a, 0), c, 0)

    # return the function flags for an address
    def cmd_get_function_flags(self, a):
        return "0x{:08X}".format(GetFunctionFlags(int(a, 0)))

    # return the address of each basicblock of the function
    def cmd_get_function_blocks(self, a):
        fc = idaapi.FlowChart(idaapi.get_func(int(a, 0)))
        return " ".join(["0x{:X}".format(b.startEA) for b in fc])

    # return list of all segments start address
    def cmd_get_segments(self):
        return " ".join(["0x{:08X}".format(a) for a in Segments()])

    # return the start address for the segment from any address within
    def cmd_get_segment_start(self, a):
        return "0x{:08X}".format(SegStart(int(a, 0)))

    # return the end address for the segment starting at a
    def cmd_get_segment_end(self, a):
        return "0x{:08X}".format(SegEnd(int(a, 0)))

    # return the name of a segment
    def cmd_get_segment_name(self, a):
        return SegName(int(a, 0))

    # return the mnemonic of an opcode at addr
    def cmd_get_op_mnemonic(self, a):
        return GetMnem(int(a, 0))

    # tell IDA to convert an address into an alignment directive
    def cmd_make_align(self, a, count, align):
        return str(MakeAlign(int(a, 0), int(count, 0), int(align, 0)))

    # tell IDA to make an array
    def cmd_make_array(self, a, count):
        return str(MakeArray(int(a, 0), int(count, 0)))

    # tell IDA to convert to a byte
    def cmd_make_byte(self, a):
        return str(MakeByte(int(a, 0)))

    # tell IDA to convert to a word
    def cmd_make_word(self, a):
        return str(MakeWord(int(a, 0)))

    # tell IDA to convert to a dword
    def cmd_make_dword(self, a):
        return str(MakeDword(int(a, 0)))

    # tell IDA to convert to a qword
    def cmd_make_qword(self, a):
        return str(MakeQword(int(a, 0)))

    # tell IDA to convert to a string
    def cmd_make_string(self, a, a_end, kind):
        return str(MakeStr(int(a, 0), int(a_end, 0), int(kind, 0)))

    # tell IDA to disassemble
    def cmd_make_code(self, a):
        return str(MakeCode(int(a, 0)))

    # undefine at an address
    def cmd_make_unknown(self, a):
        return str(MakeUnkn(int(a, 0), 1))

    # patch a raw byte in the IDB
    def cmd_patch_byte(self, a, v):
        PatchByte(int(a, 0), int(v, 0))
        return ""

    # return the path of the analysed file
    def cmd_get_input_path(self):
        return GetInputFilePath()

    # return the nth entrypoint address
    def cmd_get_entry(self, idx):
        return "0x{:08X}".format(GetEntryPoint(GetEntryOrdinal(int(idx, 0))))

    # return <cpu_name> <word size> <endianness>
    def cmd_get_cpuinfo(self):
        info = idaapi.get_inf_structure()
        cpu_name = info.procName
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

    # run many commands
    # batch is a list of separate commands
    # run all of them and return the array of results
    # array encoded as sequence of <str(int(len(element)))><space><element>
    # ex: "14 get_cursor_pos4 quit" -> "4 0x423 bye"
    def cmd_batch(self, batch):
        ans_ary = []
        off = 0
        while off < len(batch):
            off_len = batch.find(" ", off)  # way faster than split() for large strings
            ln = int(batch[off:off_len])
            off = off_len+1+ln
            rq = batch[off_len+1:off]

            ans = self.handle_rq(rq)

            ans_ary.append(ans)

        return "".join([str(len(ans)) + " " + ans for ans in ans_ary])

    # handle multiple requests/responses in the client socket
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
                buf += self.sock_client.recv(int(ln)-len(buf))

            rq = buf[:int(ln)]
            buf = buf[int(ln):]

            ans = self.handle_rq(rq)

            self.sock_client.send(str(len(ans)) + " " + ans)
            
            if " " not in buf:
                select.select([self.sock_client], [], [], 4)
                buf += self.sock_client.recv(4096)



idaremote = IdaRemote()
idaremote.listen()
idaremote.register_ida_timer()

