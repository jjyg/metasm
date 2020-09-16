require 'socket'

# ruby client for idaremote
# 'idaremote.py' plugin must be running in IDA first

class IdaClient
	attr_accessor :host, :port, :batch_ary, :multirq_fd
	def initialize(host='localhost', port=56789)
		@host = host
		@port = port
		@batch_ary = nil
		@multirq_fd = nil
	end

	# postprocessing callbacks, to transform string answers from the IDA plugin to user-friendly data
	PostProcess = {}
	# commandname => safe to ignore returned value (prevent warning in a batch)
	CanIgnoreRet = {}

	# make one request to IDA
	# in batch mode, queue the request for later
	# in non-batch mode, connect to the plugin and handle the request
	# dump network packets to stdout if $DEBUG is on
	def rq(*rq, &consumer)
		if @batch_ary
			# building a batch request, dont actually send
			@batch_ary << [rq, consumer]
			return
		end

		buf = rq.join(' ')
		if @multirq_fd
			if @multirq_fd == true
				@multirq_fd = TCPSocket.open(@host, @port)
				buf = "multirq #{buf.length} " + buf
			else
				buf = "#{buf.length} " + buf
			end
			puts "m> #{buf.inspect}" if $DEBUG
			@multirq_fd.write(buf)
			outlen = read_szprefix(@multirq_fd)
			out = @multirq_fd.read(Integer(outlen))
			puts "m< #{(outlen + out).inspect}" if $DEBUG
		else
			if buf.length > 4096
				# only multirq supports large requests
				buf = "multirq #{buf.length} " + buf + "0 "
			end
			puts "> #{buf.inspect}" if $DEBUG
			out = TCPSocket.open(@host, @port) { |s|
				s.write(buf)
				s.read
			}
			puts "< #{out.inspect}" if $DEBUG
			if buf.length > 4096
				outlen = out[0..out.index(' ')]
				out = out[outlen.length, Integer(outlen)]
			end
		end
		pp = PostProcess[rq[0]]
		out = pp.call(out) if pp
		out = consumer.call(out) if consumer
		out
	end

	def read_szprefix(fd)
		szstr = ''
		while c = fd.read(1)
			szstr << c
			break if c == ' '
		end
		szstr
	end

	# parse an address, check for BAD_ADDR
	def self.addr(a)
		a = Integer(a)
		a if a != -1
	end

	# decode a hex buffer
	def self.unhex(s)
		[s].pack('H*')
	end

	# metaprogramming to register new commands handled by the IDA plugin
	def self.add_command(name, *rq_args, &postprocess)
		PostProcess[name] = postprocess
		CanIgnoreRet[name] = true if rq_args.delete(:can_ignore_ret)
		define_method(name) { |*args, &pp|
			args << 0 while rq_args.length > args.length and rq_args[args.length].to_s[-1, 1] == '0'	# allow default 0 argument values if rq_arg is named :stuff0
			raise ArgumentError, "bad arg count for #{name}" if args.length != rq_args.length
			rq(name, *args, &pp)
		}
	end


	# actual plugin command list

	add_command('get_remoteid') { |s| { :software => s.split[0], :version => s.split[1] } }
	add_command('get_cpuinfo') { |s| { :name => s.split[0], :size => Integer(s.split[1]), :endian => s.split[2].to_sym } }
	add_command('get_label', :addr) { |s| s if s != '' }
	add_command('set_label', :addr, :label, :can_ignore_ret) { |s| s == "ok" }
	add_command('resolve_label', :label) { |a| addr(a) }
	add_command('get_named_addrs', :addr_start, :addr_end) { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_bytes', :addr, :len) { |hex| unhex(hex) }
	add_command('get_byte', :addr) { |i| Integer(i) }
	add_command('get_word', :addr) { |i| Integer(i) }
	add_command('get_dword', :addr) { |i| Integer(i) }
	add_command('get_qword', :addr) { |i| Integer(i) }
	add_command('get_xrefs_to', :addr) { |lst| lst.split.map { |a| addr(a) } }
	add_command('exit_plugin', :can_ignore_ret) { |s| s == "bye" }
	add_command('exit_ida', :exit_code0, :can_ignore_ret) { |s| s == "bye" }
	add_command('get_comment', :addr) { |s| s if s != '' }
	add_command('set_comment', :addr, :comment, :can_ignore_ret) { |s| s == "ok" }
	add_command('get_cursor_pos') { |a| addr(a) }
	add_command('set_cursor_pos', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('get_selection') { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_flags', :addr) { |f| Integer(f) }
	add_command('get_heads', :addr_start, :addr_end) { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_prev_head', :addr) { |a| addr(a) }
	add_command('get_next_head', :addr) { |a| addr(a) }
	add_command('get_item_size', :addr) { |a| Integer(a) }
	add_command('get_functions', :addr_start, :addr_end) { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_function_name', :addr) { |s| s if s != '' }
	add_command('get_function_comment', :addr) { |s| s if s != '' }
	add_command('set_function_comment', :addr, :comment, :can_ignore_ret) { |s| s == "ok" }
	add_command('get_function_flags', :addr) { |f| Integer(f) }
	add_command('get_function_blocks', :addr) { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_type', :addr) { |s| s if s != '' }
	add_command('set_type', :addr, :type, :can_ignore_ret) { |s| s if s != "ok" }
	add_command('get_segments') { |lst| lst.split.map { |a| addr(a) } }
	add_command('get_segment_start', :addr) { |a| addr(a) }
	add_command('get_segment_end', :addr) { |a| addr(a) }
	add_command('get_segment_name', :addr) { |s| s if s != '' }
	add_command('get_op_mnemonic', :addr) { |s| s if s != '' }
	add_command('make_align', :addr, :count, :align, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_array', :addr, :count, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_byte', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_word', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_dword', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_qword', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_string', :addr_start, :len0, :type0, :can_ignore_ret) { |s| s == "ok" }
	add_command('make_code', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('undefine', :addr, :can_ignore_ret) { |s| s == "ok" }
	add_command('patch_byte', :addr, :newbyte, :can_ignore_ret) { |s| s == "ok" }
	add_command('get_input_path') { |s| s if s != '' }
	add_command('get_entry', :idx0) { |a| addr(a) }

	# multirq request handling
	# keep the tcp session to IDA open between requests for the duration of the block
	def multirq(&cb)
		return cb.call(self) if @multirq_fd

		@multirq_fd = true
		out = cb.call(self)
		multirq_close
		out
	end

	# when inside a multirq request, call this to close the current cx
	# use this to avoid blocking IDA for too long
	# will be reopened on demand during the next request
	def multirq_pause
		multirq_close
		@multirq_fd = true
	end

	# close a multirq session
	def multirq_close
		if @multirq_fd and @multirq_fd != true
			puts "m> \"0 \"" if $DEBUG
			@multirq_fd.write "0 "
			puts "m< #{@multirq_fd.read.inspect}" if $DEBUG
			@multirq_fd.close
		end
		@multirq_fd = nil
	end

	# batch request handling
	# yields, all the ida requests in the block will be buffered and sent in one request
	# all the ida requests in the block must use the callback syntax to handle the returned value (asynchronous mode)
	# those callbacks may send other ida requests, these will automatically be batched, recursively
	# all the batch is done in a single TCP session with the IDA plugin, and will block IDA until the callback returns, avoid doing slow/non-ida stuff in there
	def batch(&cb)
		if @batch_ary
			# already in a batch, do nothing
			cb.call
		else
			multirq { batch_nocx(&cb) }
		end
	end
	
	# same as batch, but dont keep a TCP session open between requests
	def batch_nocx(&cb)
		prepare_batch
		out = cb.call(self)
		send_batch(true)
		out
	end

	def prepare_batch
		raise 'already in a batch !' if @batch_ary
		@batch_ary = []
	end

	def abort_batch
		raise 'not in a batch !' if not @batch_ary
		@batch_ary = nil
	end

	# actually do the batch plugin request
	# if put_cb_in_batch, restart a new batch session around the processing of the user callbacks of the current batch
	# do nothing and return false if the batch array is empty
	def send_batch(put_cb_in_batch=true)
		raise 'not in a batch !' if not @batch_ary
		ary = @batch_ary
		@batch_ary = nil
		return false if ary.empty?

		# build the actual batch remote command
		batch_rq = 'batch '
		out_pp = []
		out_cb = []
		ary.each { |rq, cb|
			rq_buf = rq.join(' ')
			if not cb and not CanIgnoreRet[rq[0]]
				puts "W: IdaClient: batch mode request #{rq[0]} with no callback, will discard answer"
			end
			batch_entry = "#{rq_buf.length} #{rq_buf}"
			out_pp << PostProcess[rq[0]]
			out_cb << cb
			batch_rq << batch_entry
		}

		# send an actual batch command
		batch_ans = rq(batch_rq)

		# split the batch response in individual request answers
		off = 0
		out = []
		while off < batch_ans.length
			off_len = batch_ans.index(' ', off)
			len = batch_ans[off..off_len].to_i
			out << batch_ans[off_len+1, len]
			off = off_len+1+len
		end

		# now 'out' holds the responses
		# call all the postprocess callbacks
		# start a new batch according to put_cb_in_batch
		prepare_batch if put_cb_in_batch
		# basic postprocessing
		out = out.zip(out_pp).map { |ans, pp| pp ? pp.call(ans) : ans }
		# user callbacks
		out.zip(out_cb).each { |ans, cb| cb.call(ans) if cb }
		send_batch if put_cb_in_batch

		true
	end


	# user-friendly helper functions
	
	# yield each segment_start, segment_end, segment_name
	# works in a batch
	def each_segment
		get_segments { |segs|
			segs.each { |seg_start|
				get_segment_end(seg_start) { |seg_end|
					get_segment_name(seg_start) { |seg_name|
						yield seg_start, seg_end, seg_name
					}
				}
			}
		}
	end

	# yield func_addr, func_name
	def each_function(a_start, a_end)
		get_functions(a_start, a_end) { |funcs|
			funcs.each { |f_addr|
				get_function_name(f_addr) { |f_name|
					yield f_addr, f_name
				}
			}
		}
	end

	# yield head_addr
	def each_head(a_start, a_end)
		get_heads(a_start, a_end) { |heads|
			heads.each { |h_addr|
				yield h_addr
			}
		}
	end

	# yield addr, name
	def each_name(a_start, a_end)
		get_named_addrs(a_start, a_end) { |addrs|
			addrs.each { |a|
				get_label(a) { |n|
					yield a, n
				}
			}
		}
	end

	# yield each pointer with its index, return the table of pointers (if called out of batch)
	def read_ptr_table(a_start, nr, &cb)
		@ptrsz ||= nil
		ary = []
		if not @ptrsz
			get_cpuinfo { |ci|
				@ptrsz = ci[:size]/8
				iter_ptr_table(a_start, nr) { |ptr, i|
					ary << ptr
					yield(ptr, i) if block_given?
				}
			}
		else
			iter_ptr_table(a_start, nr) { |ptr, i|
				ary << ptr
				yield(ptr, i) if block_given?
			}
		end
		ary
	end

	# walk a table of pointers, yield each pointer with its index
	def iter_ptr_table(a_start, nr, ptrsz=@ptrsz)
		get_ptr = (ptrsz == 4 ? :get_dword : :get_qword)
		nr.times { |i|
			send(get_ptr, a_start + i*@ptrsz) { |ptr| yield(ptr, i) }
		}
	end

	# try to set a label at addr, append integers until success
	# yield the successful label name or nil on error
	def set_label_unique(addr, label, &b)
		label = label.gsub(/[^\w]/, '')
		set_label(addr, label) { |done|
			if done
				b.call(label) if b
			else
				parts = label.split('_')
				if parts.last =~ /^\d+$/ and parts.last.to_i < 100
					count = parts.pop.to_i + 1
				else
					count = 1
				end
				if count >= 10
					# avoid infinite retries
					b.call(nil) if b
				else
					label = parts.join + "_#{count}"
					set_label_unique(addr, label, &b)
				end
			end
		}
	end
end

if __FILE__ == $0
	# if called directly from the commandline as a standalone script:
	# send one raw idaremote command from the script args
	# print the raw result
	ida = IdaClient.new
	p ida.rq(*ARGV)
end
