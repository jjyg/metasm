#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
require 'socket'

module Metasm
# lowlevel interface to the gdbserver protocol
class GdbClient
	# XXX x64/other arch
	GDBREGS = %w[eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs].map { |r| r.to_sym }	# XXX [77] = 'orig_eax'

	# compute the hex checksum used in gdb protocol
	def gdb_csum(buf)
		'%02x' % (buf.unpack('C*').inject(0) { |cs, c| cs + c } & 0xff)
	end

	# send the buffer, waits ack
	# return true on success
	def gdb_send(cmd, buf='')
		buf = cmd + buf
		buf = '$' << buf << '#' << gdb_csum(buf)
		puts "gdb_send(#{buf[0, 32].inspect}#{'...' if buf.length > 32})" if $DEBUG

		5.times {
			@io.write buf
			loop do
				if not IO.select([@io], nil, nil, 1)
					break
				end
				raise Errno::EPIPE if not ack = @io.read(1)
				case ack
				when '+'
					return true
				when '-'
					puts "gdb_send: ack neg" if $DEBUG
					break
				when nil; return
				end
			end
		}
		log "send error #{cmd.inspect} (no ack)"
		false
	end

	def quiet_during
		pq = quiet
		@quiet = true
		yield
	ensure
		@quiet = pq
	end

	# return buf, or nil on error / csum error
	# waits IO.select(timeout) between each char
	def gdb_readresp(timeout=nil)
		@recv_ctx ||= {}
		@recv_ctx[:state] ||= :nosync
		buf = nil

		while @recv_ctx
			return unless IO.select([@io], nil, nil, timeout)
			raise Errno::EPIPE if not c = @io.read(1)
			case @recv_ctx[:state]
			when :nosync
				if c == '$'
					@recv_ctx[:state] = :data
					@recv_ctx[:buf] = ''
				end
			when :data
				if c == '#'
					@recv_ctx[:state] = :csum1
					@recv_ctx[:cs] = ''
				else
					@recv_ctx[:buf] << c
				end
			when :csum1
				@recv_ctx[:cs] << c
				@recv_ctx[:state] = :csum2
			when :csum2
				cs = @recv_ctx[:cs] << c
				buf = @recv_ctx[:buf]
				@recv_ctx = nil
				if cs.downcase != gdb_csum(buf).downcase
					log "transmit error"
					@io.write '-'
					return
				end
			end
		end
		@io.write '+'

		if buf =~ /^E(..)$/
			e = $1.to_i(16)
			log "error #{e} (#{PTrace32::ERRNO.index(e)})"
			return
		end
		puts "gdb_readresp: got #{buf[0, 64].inspect}#{'...' if buf.length > 64}" if $DEBUG

		buf
	end

	def gdb_msg(*a)
		gdb_readresp if gdb_send(*a)
	end

	# rle: build the regexp that will match repetitions of a character, skipping counts leading to invalid char
	rng = [3..(125-29)]
	[?+, ?-, ?#, ?$].sort.each { |invalid|
		invalid -= 29
		rng.each_with_index { |r, i|
			if r.include? invalid
				replace = [r.begin..invalid-1, invalid+1..r.end]
				replace.delete_if { |r_| r_.begin > r_.end }
				rng[i, 1] = replace
			end
		}
	}
	repet = rng.reverse.map { |r| "\\1{#{r.begin},#{r.end}}" }.join('|')
	RLE_RE = /(.)(#{repet})/m

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
		buf = buf[/^[a-fA-F0-9]*/]
		buf = '0' + buf if buf.length & 1 == 1
		[buf].pack('H*')
	end

	# retrieve remote regs
	def read_regs
		if buf = gdb_msg('g')
			regs = unhex(unrle(buf))
			if regs.length < GDBREGS.length*4
				# retry once, was probably a response to something else
				puts "bad regs size!" if $DEBUG
				buf = gdb_msg('g')
				regs = unhex(unrle(buf)) if buf
				if not buf or regs.length < GDBREGS.length*4
					raise "regs buffer recv is too short !"
				end
			end
			Hash[GDBREGS.zip(regs.unpack('L*'))]
		end
	end

	# send the reg values
	def send_regs(r = {})
		return if r.empty?
		regs = r.values_at(*GDBREGS)
		gdb_msg('G', hex(regs.pack('L*')))
	end

	# read memory (small blocks prefered)
	def getmem(addr, len)
		return '' if len == 0
		if mem = quiet_during { gdb_msg('m', hexl(addr) << ',' << hexl(len)) }
			unhex(unrle(mem))
		end
	end

	# write memory (small blocks prefered)
	def setmem(addr, data)
		len = data.length
		return if len == 0
		raise 'writemem error' if not gdb_msg('M', hexl(addr) << ',' << hexl(len) << ':' << rle(hex(data)))
	end

	def continue
		gdb_send('c')
	end

	def singlestep
		gdb_send('s')
	end

	def break
		@io.write("\3")
	end

	def kill
		gdb_send('k')
	end

	def detach
		gdb_send('D')
	end

	attr_accessor :io
	def initialize(io)
		case io
		when IO; @io = io
		when /^udp:([^:]*):(\d+)$/; @io = UDPSocket.new ; @io.connect($1, $2)
		when /^(?:tcp:)?([^:]*):(\d+)$/; @io = TCPSocket.open($1, $2)
		else raise "unknown target #{io.inspect}"
		end

		gdb_setup
	end

	def gdb_setup
		gdb_msg('q', 'Supported')
		#gdb_msg('Hc', '-1')
		#gdb_msg('qC')
		if not gdb_msg('?')
			log "nobody on the line, waiting for someone to wake up"
			IO.select([@io], nil, nil, nil)
			log "who's there ?"
		end
	end

	def set_hwbp(type, addr, len=1, set=true)
		set = (set ? 'Z' : 'z')
		type = { 'r' => '3', 'w' => '2', 'x' => '1', 's' => '0' }[type.to_s] || raise("invalid bp type #{type.inspect}")
		gdb_msg(set, type << ',' << hexl(addr) << ',' << hexl(len))
		true
	end

	def unset_hwbp(type, addr, len=1)
		set_hwbp(type, addr, len, false)
	end

	# use qSymbol to retrieve a symbol value (uint)
	def request_symbol(name)
		resp = gdb_msg('qSymbol:', hex(name))
		if resp and a = resp.split(':')[1]
			unhex(a).unpack('N').first
		end
	end

	def check_target(timeout=0)
		return if not msg = gdb_readresp(timeout)
		case msg[0]
		when ?T
			sig = unhex(msg[1, 2])[0]
			ret = { :state => :stopped, :info => "signal #{sig} #{Signal.list.index(sig) rescue nil}" }	# XXX windows host & signame?
			ret.update msg[3..-1].split(';').inject({}) { |h, s| k, v = s.split(':', 2) ; h.update k => (v || true) }	# 'thread' -> pid
		when ?S
			sig = unhex(msg[1, 2])[0]
			{ :state => :stopped, :info => "signal #{sig} #{Signal.list.index(sig) rescue nil}" }
		else
			log "check_target: unhandled #{msg.inspect}"
			{ :state => :unknown }
		end
	end

	attr_accessor :logger, :quiet
	def log(s)
		return if quiet
		@logger ||= $stdout
		@logger.puts s
	end
end

# virtual string to access the remote process memory
class GdbRemoteString < VirtualString
	attr_accessor :gdb

	def initialize(gdb, addr_start=0, length=0xffff_ffff)
		@gdb = gdb
		@pagelength = 512
		super(addr_start, length)
	end

	def dup(addr=@addr_start, len=@length)
		self.class.new(@gdb, addr, len)
	end

	def rewrite_at(addr, data)
		len = data.length
		off = 0
		while len > @pagelength
			@gdb.setmem(addr+off, data[off, @pagelength])
			off += @pagelength
			len -= @pagelength
		end
		@gdb.setmem(addr+off, data[off, len])
	end

	def get_page(addr, len=@pagelength)
		@gdb.getmem(addr, len)
	end
end

# this class implements a high-level API using the gdb-server network debugging protocol
class GdbRemoteDebugger < Debugger
	attr_accessor :gdb
	def initialize(url, mem=nil)
		@gdb = GdbClient.new(url)
		@gdb.logger = self
		# TODO get current cpu
		@cpu = Ia32.new
		@memory = mem || GdbRemoteString.new(@gdb)
		@reg_val_cache = {}
		@regs_dirty = false
		super()
	end

	def invalidate
		sync_regs
		@reg_val_cache.clear
		super()
	end

	def get_reg_value(r)
		return @reg_val_cache[r] || 0 if @state != :stopped
		sync_regs
		@reg_val_cache = @gdb.read_regs || {} if @reg_val_cache.empty?
		@reg_val_cache[r] || 0
	end
	def set_reg_value(r, v)
		@reg_val_cache[r] = v
		@regs_dirty = true
	end

	def sync_regs
		@gdb.send_regs(@reg_val_cache) if @regs_dirty and not @reg_val_cache.empty?
		@regs_dirty = false
	end

	def do_check_target
		return if @state == :dead
		t = Time.now
		@last_check_target ||= t
		if @state == :running and t - @last_check_target > 1
			@gdb.io.write '$?#' << @gdb.gdb_csum('?')
			@last_check_target = t
		end
		return unless i = @gdb.check_target(0)
		@state, @info = i[:state], i[:info]
		@info = nil if @info =~ /TRAP/
	end

	def do_wait_target
		return unless i = @gdb.check_target(nil)
		@state, @info = i[:state], i[:info]
		@info = nil if @info =~ /TRAP/
	end

	def do_continue(*a)
		return if @state != :stopped
		@state = :running
		@info = 'continue'
		@gdb.continue
		@last_check_target = Time.now
	end

	def do_singlestep(*a)
		return if @state != :stopped
		@state = :running
		@info = 'singlestep'
		@gdb.singlestep
		@last_check_target = Time.now
	end

	def break
		@gdb.break
	end

	def kill(sig=nil)
		# TODO signal nr
		@gdb.kill
		@state = :dead
		@info = 'killed'
	end

	def detach
		super()	# remove breakpoints & stuff
		@gdb.detach
		@state = :dead
		@info = 'detached'
	end
	
	# set to true to use the gdb msg to handle bpx, false to set 0xcc ourself
	attr_accessor :gdb_bpx
	def enable_bp(addr)
		return if not b = @breakpoint[addr]
		b.state = :active
		case b.type
		when :bpx
			if gdb_bpx
				@gdb.set_hwbp('s', addr, 1)
			else
				@cpu.dbg_enable_bp(self, addr, b)
			end
		when :hw
			@gdb.set_hwbp(b.mtype, addr, b.mlen)
		end
	end

	def disable_bp(addr)
		return if not b = @breakpoint[addr]
		b.state = :inactive
		case b.type
		when :bpx
			if gdb_bpx
				@gdb.unset_hwbp('s', addr, 1)
			else
				@cpu.dbg_disable_bp(self, addr, b)
			end
		when :hw
			@gdb.unset_hwbp(b.mtype, addr, b.mlen)
		end
	end

	def check_pre_run(*a)
		sync_regs
		super(*a)
	end

	def check_post_run(*a)
		@cpu.dbg_check_post_run(self) if not gdb_bpx
		super(*a)
	end

	def loadallsyms
		puts 'loadallsyms unsupported'
	end
end
end
