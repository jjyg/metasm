#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this is a rubstop-api compatible Gdb stub
# it can connect to a gdb server and interface with the lindebug frontend
# linux/x86 only
#

require 'socket'
require 'metasm'

class GdbRemoteString < Metasm::VirtualString
	attr_accessor :gdbg

	def initialize(gdbg, addr_start=0, length=0xffff_ffff)
		@gdbg = gdbg
		@pagelength = 512
		super(addr_start, length)
	end

	def dup(addr=@addr_start, len=@length)
		self.class.new(@gdbg, addr, len)
	end

	def rewrite_at(addr, data)
		len = data.length
		off = 0
		while len > @pagelength
			@gdbg.setmem(addr+off, data[off, @pagelength])
			off += @pagelength
			len -= @pagelength
		end
		@gdbg.setmem(addr+off, data[off, len])
	end

	def get_page(addr)
		@gdbg.getmem(addr, @pagelength)
	end
end

class Rubstop
	EFLAGS = {0 => 'c', 2 => 'p', 4 => 'a', 6 => 'z', 7 => 's', 9 => 'i', 10 => 'd', 11 => 'o'}
	GDBREGS = %w[eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs]
	# define accessors for registers
	GDBREGS.each { |reg|
		define_method(reg) { regs_cache[reg] }
		define_method(reg + '=') { |v| regs_cache[reg] = v ; regs_dirty }
	}

	# compute the hex checksum used in gdb protocol
	def gdb_csum(buf)
		'%02x' % (buf.unpack('C*').inject(0) { |cs, c| cs + c } & 0xff)
	end

	# send the buffer, waits ack
	# return true on success
	def gdb_send(cmd, buf='')
		buf = cmd + buf
		buf = '$' << buf << '#' << gdb_csum(buf)
		log "gdb_send(#{buf[0, 32].inspect}#{'...' if buf.length > 32})" if $DEBUG

		5.times {
			@io.write buf
			ack = @io.read(1)
			case ack
			when '+'
				return true
			when '-'
				log "gdb_send: ack neg" if $DEBUG
			else
				log "gdb_send: ack unknown #{ack.inspect}" if $DEBUG
			       	break
			end
		}
		log "send error (no ack)"
		false
	end

	# return buf, or nil on error / csum error
	def gdb_readresp
		state = :nosync
		buf = ''
		cs = ''
		while state != :done
			# XXX timeout etc
			c = @io.read(1)
			case state
			when :nosync
				if c == '$'
					state = :data
				end
			when :data
				if c == '#'
					state = :csum1
				else
					buf << c
				end
			when :csum1
				cs << c
				state = :csum2
			when :csum2
				cs << c
				state = :done
				if cs != gdb_csum(buf)
					log "transmit error"
					@io.write '-'
					return
				end
			end
		end
		@io.write '+'

		if buf =~ /^E\d\d$/
			log "error #{buf}"
			return
		end
		log "gdb_readresp: got #{buf[0, 64].inspect}#{'...' if buf.length > 64}" if $DEBUG

		buf
	end

	def gdb_msg(*a)
		if gdb_send(*a)
			gdb_readresp
		end
	end

	# rle: build the regexp that will match repetitions of a character, skipping counts leading to invalid char
	rng = [3..(125-29)]
	[?+, ?-, ?#, ?$].sort.each { |invalid|
		invalid -= 29
		rng.each_with_index { |r, i|
			if r.include? invalid
				replace = [r.begin..invalid-1, invalid+1..r.end]
				replace.delete_if { |r| r.begin > r.end }
				rng[i, 1] = replace
			end
		}
	}
	repet = rng.reverse.map { |r| "\\1{#{r.begin},#{r.end}}" }.join('|')
	RLE_RE = /(.)(#{repet})/

	# rle-compress a buffer
	# a character followed by '*' followed by 'x' is asc(x)-28 repetitions of the char
	# eg '0* ' => '0' * (asc(' ') - 28) = '0000'
	# for the count character, it must be 32 <= char < 126 and not be '+' '-' '#' or '$'
	def rle(buf)
		buf.gsub(RLE_RE) {
			chr, len = $1, $2.length+1
			chr + '*' + (len+28).chr
		}
	end
	# decompress rle-encoded data
	def unrle(buf) buf.gsub(/(.)\*(.)/) { $1 * ($2[0]-28) } end
	# send an integer as a long hex packed with leading 0 stripped
	def hexl(int) [int].pack('N').unpack('H*').first.gsub(/^0+(.)/, '\1') end
	# send a binary buffer as a rle hex-encoded
	def hex(buf) buf.unpack('H*').first end
	# decode an rle hex-encoded buffer
	def unhex(buf)
		buf = '0' + buf if buf.length % 1 == 1
	       	[buf].pack('H*')
	end

	# on-demand local cache of registers
	def regs_cache
		readregs if @regs_cache.empty?
		@regs_cache
	end

	# retrieve remote regs
	def readregs
		sync_regs
		if buf = gdb_msg('g')
			@regs_dirty = false
			regs = unhex(unrle(buf)).unpack('L*')
			@regs_cache = Hash[GDBREGS.zip(regs)]
		end
		@curinstr = nil if @regs_cache['eip'] != @oldregs['eip']
	end

	# mark local cache of regs as modified, need to send it before continuing execution
	def regs_dirty
		@regs_dirty = true
	end

	# send the local copy of regs if dirty
	def sync_regs
		if not @regs_cache.empty? and @regs_dirty
			send_regs
		end
	end

	# send the local copy of regs
	def send_regs
		return if @regs_cache.empty?
		regs = @regs_cache.values_at(*GDBREGS)
		@regs_dirty = false
		gdb_msg('G', hex(regs.pack('L*')))
	end

	# read memory (small blocks prefered)
	def getmem(addr, len)
		return '' if len == 0
		if mem = gdb_msg('m', hexl(addr) << ',' << hexl(len))
			unhex(unrle(mem))
		else
		#	0.chr * len
		end
	end

	# write memory (small blocks prefered)
	def setmem(addr, data)
		len = data.length
		return if len == 0
		gdb_msg('M', hexl(addr) << ',' << hexl(len) << ':' << rle(hex(data)))
	end

	# read arbitrary blocks of memory (chunks to getmem)
	def [](addr, len)
		@pgm.encoded[addr, len].data
	end

	# write arbitrary blocks of memory (chunks to getmem)
	def []=(addr, len, str)
		@pgm.encoded[addr, len] = str
	end

	def curinstr
		@curinstr ||= mnemonic_di
	end

	def mnemonic_di(addr = eip)
		@pgm.encoded.ptr = addr
		di = @pgm.cpu.decode_instruction(@pgm.encoded, addr)
		@curinstr = di if addr == @regs_cache['eip']
		di
	end

	def mnemonic(addr = eip)
		mnemonic_di(addr).instruction
	end

	def pre_run
		@oldregs = regs_cache.dup
		sync_regs
	end

	def post_run
		@regs_cache.clear
		@curinstr = nil
		@mem.invalidate
	end

	def cont
		pre_run
		do_singlestep if @wantbp
		gdb_msg('c')
		post_run
		ccaddr = eip-1
		if @breakpoints[ccaddr] and self[ccaddr, 1] == "\xcc"
			self[ccaddr, 1] = @breakpoints.delete ccaddr
			mem.invalidate
			self.eip = ccaddr
			@wantbp = ccaddr if not @singleshot.delete ccaddr
		end
	end

	def singlestep
		pre_run
		do_singlestep
		post_run
	end

	def do_singlestep
		gdb_msg('s')
		if @wantbp
			self[@wantbp, 1] = "\xcc"
			@wantbp = nil
		end
	end

	def stepover
		i = curinstr.instruction if curinstr
		if i and (i.opname == 'call' or (i.prefix and i.prefix[:rep]))
			eaddr = eip + curinstr.bin_length
			bpx eaddr, true
			cont
		else
			singlestep
		end
	end

	def stepout
		stepover until curinstr.opcode.name == 'ret'
		singlestep
	end

	def bpx(addr, singleshot=false)
		return if @breakpoints[addr]
		@singleshot[addr] = true if singleshot
		@breakpoints[addr] = self[addr, 1]
		self[addr, 1] = "\xcc"
	end


	def kill
		gdb_send('k')
	end

	def detach
		# TODO
	end

	attr_accessor :pgm, :breakpoints, :singleshot, :wantbp,
		:symbols, :symbols_len, :filemap, :oldregs, :io, :mem
	def initialize(io)
		case io
		when IO; @io = io
		when /^udp:([^:]*):(\d+)$/; @io = UDPSocket.new ; @io.connect($1, $2)
		when /^(?:tcp:)?([^:]*):(\d+)$/; @io = TCPSocket.open($1, $2)
		else raise "unknown target #{io.inspect}"
		end
		@pgm = Metasm::ExeFormat.new Metasm::Ia32.new
		@mem = GdbRemoteString.new self
		@pgm.encoded = Metasm::EncodedData.new @mem
		@regs_cache = {}
		@regs_dirty = nil
		@oldregs = {}
		@breakpoints = {}
		@singleshot = {}
		@wantbp = nil
		@symbols = {}

		gdb_setup
	end

	def gdb_setup
		#gdb_msg('q', 'Supported')
		#gdb_msg('?')
		#gdb_msg('H', 'c-1')
		#gdb_msg('q', 'C')
	end


	def findfilemap(s)
		'???'
	end

	def findsymbol(k)
		'???!%08x' % k
	end

	def set_hwbp(type, addr, len=1)
		log 'not implemented'
		false
	end

	def loadsyms(baseaddr, name)
	end

	def loadallsyms
	end

	def scansyms
	end

	def backtrace
		bt = []
		bt << findsymbol(eip)
		fp = ebp
		while fp >= esp and fp <= esp+0x100000
			bt << findsymbol(self[fp+4, 4].unpack('L').first)
			fp = self[fp, 4].unpack('L').first
		end
		bt
	end

	attr_accessor :logger
	def log(s)
		@logger ||= $stdout
		@logger.puts s
	end

	def checkbp ; end
end
