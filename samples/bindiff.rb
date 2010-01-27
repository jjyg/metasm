#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
require 'optparse'

module Metasm
class BinDiffWidget < Metasm::Gui::DrawableWidget
	attr_accessor :dasm1, :dasm2
	attr_accessor :status

	COLORS = { :same => '8f8', :similar => 'cfc', :badarg => 'fcc', :badop => 'faa', :default => '888' }

	def initialize_widget(d1, d2)
		@dasm1, @dasm2 = d1, d2
		@dasmcol1 = {}
		@dasmcol2 = {}
		@dasm1.gui.bg_color_callback = lambda { |a1| COLORS[@dasmcol1[a1] || :default] }
		@dasm2.gui.bg_color_callback = lambda { |a2| COLORS[@dasmcol2[a2] || :default] }
		@status = nil
	end

	def paint
		help = "i: matchfuncs  d: dasm"
		draw_string_color(:grey, @font_width, @font_height, help)
		draw_string_color(:black, @font_width, 3*@font_height, @status || 'idle')
	end

	def gui_update
		@dasm1.gui.gui_update rescue nil
		@dasm2.gui.gui_update rescue nil
		redraw
	end

	def set_status(st=nil)
		ost = @status
		@status = st
		redraw
		if block_given?
			ret = protect { yield }
			set_status ost
			ret
		end
	end

	def keypress(key)
		case key
		when ?A
			keypress(?D)
			keypress(?f)
			keypress(?i)
		when ?D
			@dasm1.load_plugin 'dasm_all'
			@dasm2.load_plugin 'dasm_all'

			set_status('dasm_all 1') {
				@dasm1.dasm_all_section '.text'
			}

			set_status('dasm_all 2') {
				@dasm2.dasm_all_section '.text'
			}
			gui_update
		when ?d
			set_status('dasm 1') {
				@dasm1.disassemble_fast_deep(@dasm1.gui.curaddr)
				@dasm1.function[@dasm1.gui.curaddr] = Metasm::DecodedFunction.new
				@dasm1.gui.focus_addr(@dasm1.gui.curaddr, :graph)
			}
			set_status('dasm 2') {
				@dasm2.disassemble_fast_deep(@dasm2.gui.curaddr)
				@dasm2.function[@dasm2.gui.curaddr] = Metasm::DecodedFunction.new
				@dasm2.gui.focus_addr(@dasm2.gui.curaddr, :graph)
			}
			gui_update
		when ?f
			set_status('find funcs') {
				@func1 = create_funcs(@dasm1)
				puts "d1: #{@func1.length} funcs"
				@func2 = create_funcs(@dasm2)
				puts "d2: #{@func2.length} funcs"
				@funcstat1 = create_funcs_stats(@func1, @dasm1)
				@funcstat2 = create_funcs_stats(@func2, @dasm2)
			}
		when ?g
			inputbox('address to go', :text => Expression[@dasm1.gui.curaddr]) { |v|
				@dasm1.gui.focus_addr_autocomplete(v)
				@dasm2.gui.focus_addr_autocomplete(v)
			}
		when ?i
			keypress(?f) if not @funcstat2

			m = set_status('match funcs') {
				match_funcs
			}

			gui_update
			Gui.main_iter
			list = [['addr 1', 'addr 2', 'score']]
			f1 = @func1.keys
			f2 = @func2.keys
			m.each { |a1, (a2, s)|
				list << [(@dasm1.get_label_at(a1) || Expression[a1]), (@dasm2.get_label_at(a2) || Expression[a2]), '%.4f' % s]
				f1.delete a1
				f2.delete a2
			}
			f1.each { |a1| list << [(@dasm1.get_label_at(a1) || Expression[a1]), '?', 'nomatch'] }
			f2.each { |a2| list << ['?', (@dasm2.get_label_at(a2) || Expression[a2]), 'nomatch'] }
			listwindow("matches", list) { |i| @dasm1.gui.focus_addr i[0], nil, true ; @dasm2.gui.focus_addr i[1], nil, true }
		when ?m
			s = match_func(@dasm1.gui.curaddr, @dasm2.gui.curaddr, true, true)
			puts "match score: #{s}"
			gui_update

		when ?r
			puts 'reload'
			load __FILE__
			gui_update

		when ?Q
			Gui.main_quit
		end
	end

	def keypress_ctrl(key)
		case key
		when ?r
			inputbox('code to eval') { |c| messagebox eval(c).inspect[0, 512], 'eval' }
		end
	end

	# func addr => { funcblock => list of funcblock to }
	def create_funcs(dasm)
		f = {}
		dasm.function.each_key { |a|
			next if not dasm.decoded[a].kind_of? DecodedInstruction
			f[a] = create_func(dasm, a)
			Gui.main_iter
		}
		f
	end

	def create_func(dasm, a)
		h = {}
		todo = [a]
		while a = todo.pop
			next if h[a]
			h[a] = []
			dasm.decoded[a].block.each_to_samefunc(dasm) { |ta|
				next if not dasm.decoded[ta].kind_of? DecodedInstruction
				todo << ta
				h[a] << ta
			}
		end
		h
	end

	def create_funcs_stats(f, dasm)
		fs = {}
		f.each { |a, g|
			fs[a] = create_func_stats(dasm, a, g)
			Gui.main_iter
		}
		fs
	end

	def create_func_stats(dasm, a, g)
		s = {}
		s[:blocks] = g.length

		s[:edges] = 0	# nr of edges
		s[:leaves] = 0	# nr of nodes with no successor
		s[:ext_calls] = 0	# nr of jumps out_of_func
		s[:loops] = 0	# nr of jump back

		todo = [a]
		done = []
		while aa = todo.pop
			next if done.include? aa
			done << aa
			todo.concat g[aa]

			s[:edges] += g[aa].length
			s[:leaves] += 1 if g[aa].empty?
			dasm.decoded[aa].block.each_to_otherfunc(dasm) { s[:ext_calls] += 1 }
		end

		# loop detection
		# find the longest distance to the root w/o loops
		g = g.dup
		while eliminate_one_loop(a, g)
			s[:loops] += 1
		end

		s
	end

	def eliminate_one_loop(a, g)
		stack = []
		index = {}
		reach_index = {}
		done = false

		curindex = 0
		
		trajan = lambda { |e|
			index[e] = curindex
			reach_index[e] = curindex
			curindex += 1
			stack << e
			g[e].each { |ne|
				if not index[ne]
					trajan[ne]
					break if done
					reach_index[e] = [reach_index[e], reach_index[ne]].min
				elsif stack.include? ne
					reach_index[e] = [reach_index[e], reach_index[ne]].min
				end
			}
			break if done
			if index[e] == reach_index[e]
				if (e == stack.last and not g[e].include? e)
					stack.pop
					next
				end
				# e is the entry in the loop, cut the loop here
				tail = reach_index.keys.find { |ee| reach_index[ee] == index[e] and g[ee].include? e }
				g[tail] -= [e]	# patch g, but don't modify the original g value (ie -= instead of delete)
				done = true	# one loop found & removed, try again
			end
		}

		trajan[a]
		done
	end

	def match_funcs
		return if not @funcstat1
		layout_match = {}

		@funcstat1.each { |a, s|
			layout_match[a] = []
			@funcstat2.each { |aa, ss|
				layout_match[a] << aa if s == ss
			}
			Gui.main_iter
		}

		# refine the layout matching with actual function matching
		already_matched = []
		match = {}
		match_score = {}
		layout_match.each { |f1, list|
			f2 = (list - already_matched).sort_by { |f| match_func(f1, f) }.first
			if f2
				already_matched << f2
				score = match_func(f1, f2, true)
				match[f1] = [f2, score]
			end
			Gui.main_iter
		}

		puts "matched #{match.length} - unmatched #{@func1.length - match.length}"

		match
	end

	# return how much match a func in d1 and a func in d2
	def match_func(a1, a2, do_colorize=false, verb=false)
		f1 = @func1[a1]
		f2 = @func2[a2]
		todo1 = [a1]
		todo2 = [a2]
		done1 = []
		done2 = []
		score = 0.0	# average of the (local best) match_block scores
		score += 0.01 if @dasm1.get_label_at(a1) != @dasm2.get_label_at(a2)	# for thunks
		score_div = [f1.length, f2.length].max.to_f
		# XXX this is stupid and only good for perfect matches (and even then it may fail)
		# TODO handle block split etc (eg instr-level diff VS block-level)
		while a1 = todo1.shift
			next if done1.include? a1
			t = todo2.map { |a| [a, match_block(@dasm1.decoded[a1].block, @dasm2.decoded[a].block)] }
			a2 = t.sort_by { |a, s| s }.first
			if not a2
				break
			end
			score += a2[1] / score_div
			a2 = a2[0]
			done1 << a1
			done2 << a2
			todo1.concat f1[a1]
			todo2.concat f2[a2]
			todo2 -= done2
			colorize_blocks(a1, a2) if do_colorize
		end

		score += (f1.length - f2.length).abs * 3 / score_div	# block count difference -> +3 per block

		score
	end

	def match_block(b1, b2)
		# 0 = perfect match (same opcodes, same args)
		# 1 = same opcodes, same arg type
		# 2 = same opcodes, diff argtypes
		# 3 = some opcode difference
		# 4 = full block difference
		score = 0
		score_div = [b1.list.length, b2.list.length].max.to_f
		common_start = 0
		common_end = 0

		# basic diff-style: compare start while it's good, then end, then whats left
		# should handle most simples cases well
		len = [b1.list.length, b2.list.length].min
		while common_start < len and (s = match_instr(b1.list[common_start], b2.list[common_start])) <= 1
			score += s / score_div
			common_start += 1
		end

		while common_start+common_end < len and (s = match_instr(b1.list[-1-common_end], b2.list[-1-common_end])) <= 1
			score += s / score_div
			common_end += 1
		end

		# TODO improve the middle part matching (allow insertions/suppressions/swapping)
		b1.list[common_start..-1-common_end].zip(b2.list[common_start..-1-common_end]).each { |di1, di2|
			score += match_instr(di1, di2) / score_div
		}

		yield(common_start, common_end) if block_given?	# used by colorize_blocks

		score += (b1.list.length - b2.list.length).abs * 3 / score_div	# instr count difference -> +3 per instr

		score
	end

	def colorize_blocks(a1, a2)
		b1 = @dasm1.decoded[a1].block
		b2 = @dasm2.decoded[a2].block

		common_start = common_end = 0
		match_block(b1, b2) { |a, b| common_start = a ; common_end = b }

		b1.list[0..-1-common_end].zip(b2.list[0..-1-common_end]).each { |di1, di2|
			next if not di1 or not di2
			@dasmcol1[di1.address] = @dasmcol2[di2.address] = [:same, :similar, :badarg, :badop][match_instr(di1, di2)]
		}
		b1.list[-common_end..-1].zip(b2.list[-common_end..-1]).each { |di1, di2|
			next if not di1 or not di2
			@dasmcol1[di1.address] = @dasmcol2[di2.address] = [:same, :similar, :badarg, :badop][match_instr(di1, di2)]
		}
	end

	def match_instr(di1, di2)
		if not di1 or not di2 or di1.opcode.name != di2.opcode.name
			3
		elsif di1.instruction.args.map { |a| a.class } != di2.instruction.args.map { |a| a.class }
			2
		elsif di1.instruction.to_s != di2.instruction.to_s
			1
		else
			0
		end
	end
end

class BinDiffWindow < Gui::Window
	def initialize_window(d1, d2)
		self.widget = BinDiffWidget.new(d1, d2)
	end
end
end

# allow reloading the file
if not defined? $running
$running = true

$VERBOSE = true

# parse arguments
opts = {}
OptionParser.new { |opt|
	opt.banner = 'Usage: bindiff.rb [options] <executable> [<entrypoints>]'
	opt.on('-P <plugin>', '--plugin <plugin>', 'load a metasm disassembler plugin') { |h| (opts[:plugin] ||= []) << h }
	opt.on('-e <code>', '--eval <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
	opt.on('--map1 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map1] = f }
	opt.on('--map2 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map2] = f }
	opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
	opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
	opt.on('-v', '--verbose') { $VERBOSE = true }	# default
	opt.on('-q', '--no-verbose') { $VERBOSE = false }
	opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

exename1 = ARGV.shift
w1 = Metasm::Gui::DasmWindow.new("#{exename1} - bindiff1 - metasm disassembler")
exe1 = w1.loadfile(exename1)
if opts[:autoload]
	basename1 = exename1.sub(/\.\w\w?\w?$/, '')
	opts[:map1] ||= basename1 + '.map' if File.exist?(basename1 + '.map')
	opts[:cheader] ||= basename1 + '.h' if File.exist?(basename1 + '.h')
end

exename2 = ARGV.shift
w2 = Metasm::Gui::DasmWindow.new("#{exename2} - bindiff2 - metasm disassembler")
exe2 = w2.loadfile(exename2)
if opts[:autoload]
	basename2 = exename2.sub(/\.\w\w?\w?$/, '')
	opts[:map2] ||= basename2 + '.map' if File.exist?(basename2 + '.map')
	opts[:cheader] ||= basename2 + '.h' if File.exist?(basename2 + '.h')
end

dasm1 = exe1.init_disassembler
dasm1.load_map opts[:map1] if opts[:map1]
dasm1.parse_c_file opts[:cheader] if opts[:cheader]
dasm2 = exe2.init_disassembler
dasm2.load_map opts[:map2] if opts[:map2]
dasm2.parse_c_file opts[:cheader] if opts[:cheader]

ep = ARGV.dup

w1.dasm_widget.focus_addr ep.first if not ep.empty?
w2.dasm_widget.focus_addr ep.first if not ep.empty?

opts[:plugin].to_a.each { |p| dasm1.load_plugin(p) ; dasm2.load_plugin(p) }
opts[:hookstr].to_a.each { |f| eval f }

ep.each { |e| dasm1.disassemble_fast_deep(e) ; dasm2.disassemble_fast_deep(e) }

Metasm::BinDiffWindow.new(dasm1, dasm2)

Metasm::Gui.main

end
