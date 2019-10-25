require 'idaclient'
require 'metasm'

# load in metasm the same binary as currently loaded in IDA
# from IDA, get all xrefs to the function under the cursor
#           retrieve the address of each function for each xref
# disassemble these functions in metasm
# backtrace the 'ebx' argument value for each xref
# update IDA with a comment at the call sites with the values found

ida = IdaClient.new

# retrieve preliminary info from IDA
puts "loading binary in metasm"
cur_binary = ida.get_input_path
dasm = Metasm::AutoExe.decode_file(cur_binary).disassembler
target_func = ida.get_cursor_pos
backtrace_expr = dasm.cpu.size == 32 ? :ebx : :rbx

# retrieve all xrefs, and the associated function start / function blocks
all_blocks = []
all_xrefs = []
seen_func = {}
ida.batch {
	ida.get_xrefs_to(target_func) { |xrs|
		xrs.each { |xr|
			all_xrefs << xr
			ida.get_function_name(xr) { |xr_func_name|
				next if seen_func[xr_func_name]
				seen_func[xr_func_name] = true
				ida.resolve_label(xr_func_name) { |xr_func_addr|
					# ensure we dasm from func entry first
					all_blocks << xr_func_addr
					# retrieve all blocks from the function as seen by IDA (to handle jmp tables, exception routines etc)
					ida.get_function_blocks(xr_func_addr) { |blk|
						all_blocks.concat blk
					}
				}
			}
		}
	}
}

# disassemble these in metasm, dont dasm subfunctions
puts "disassemble #{all_blocks.length} blocks"
all_blocks.each { |f|
	dasm.disassemble_fast(f)
}

# make backtracking over ignored subfunctions work
dasm.each_instructionblock { |b|
	if b.to_subfuncret and b.to_subfuncret != []
		b.each_to_normal { |t|
			dasm.function[t] ||= dasm.function[:default]
		}
	end
}

# backtrace
comments = {}
all_xrefs.each { |xr|
	bt = dasm.backtrace(backtrace_expr, xr)
	# keep only values that we could resolve to a numeric value
	values = bt.map { |val| dasm.normalize(val) }.grep(::Integer)
	next if values.empty?
	values_cmt = values.map { |val| '%x' % val }.join('/')
	comments[xr] = "#{backtrace_expr}=#{values_cmt}"
	puts "#{dasm.di_at(xr)}  ; #{comments[xr]}"
}

# add comments to the IDB
ida.batch {
	comments.each { |xr, cmt|
		ida.set_comment(xr, cmt)
	}
}

