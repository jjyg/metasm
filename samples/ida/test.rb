#!/usr/bin/ruby


# test all commands of idaclient, except exit_plugin/exit_ida
# you should discard the IDB after the test is run (adds random comments etc)

require File.expand_path('../idaclient', __FILE__)

ida = IdaClient.new

$tests_done = {}
def test_flags(str, val, expect)
	return if $tests_done[str]
	$tests_done[str] = true
	if val == expect
		puts "#{str} ok"
	else
		puts "#{str} fail #{'%x' % val}"
	end
end

rid = ida.get_remoteid
puts "testing #{rid.inspect}"

$batch = 0
ida.batch {
	ida.get_cursor_pos { |cp| $cp = cp }
	ida.get_cursor_pos { |cp| $batch |= 1 if $cp and $cp > 0 and $cp == cp; test_flags("batch", $batch, 1) }

	ida.resolve_label("test_idaremote") { |a| ida.set_label(a, "") if a }
}

ida.batch {
	$label = 0
	ida.set_label($cp, "test_idaremote")
	ida.resolve_label("test_idaremote") { |a| $label |= 1 if a == $cp }
	ida.get_named_addrs($cp-1, $cp+1) { |lst| $label |= 2 if lst.include?($cp) }
	ida.get_label($cp) { |l| $label |= 4 if l == "test_idaremote"; ida.set_label($cp, ''); test_flags("label", $label, 1|2|4) }

	$getdata = 0
	$raw = ''
	ida.get_bytes($cp, 16) { |raw| $raw = raw; $getdata |= 1 if raw.length == 16 }
	ida.get_byte($cp) { |d| $getdata |= 2 if d == $raw.unpack('C').first }
	ida.get_word($cp) { |d| $getdata |= 4 if d == $raw.unpack('v').first }
	ida.get_dword($cp) { |d| $getdata |= 8 if d == $raw.unpack('V').first }
	ida.get_qword($cp) { |d| $getdata |= 16 if d == $raw.unpack('Q').first; test_flags("getdata", $getdata, 1|2|4|8|16) }

	$seg = 0
	ida.get_segments { |segs|
		segs.each { |segstart|
			ida.get_segment_start(segstart) { |ss|
				$seg |= 1 if ss == segstart
				ida.get_segment_end(segstart) { |se|
					$seg |= 2 if se > ss
					ida.get_segment_name(segstart) { |sn|
						$seg |= 4 if sn
						test_flags("segs", $seg, 1|2|4)
					}
				}
			}
		}
	}

	$func = 0
	ida.get_entry(0) { |oep|
		ida.get_segment_start(oep) { |ss|
			ida.get_segment_end(oep) { |se|
				ida.get_functions(ss, se) { |funcs|
					funcs[0, 20].each { |f|
						ida.get_function_name(f) { |fn| $func |= 1 if fn }
						ida.get_function_comment(f) { |fc| $func |= 2 }
						ida.set_function_comment(f, "test comment")
						ida.get_function_flags(f) { |ff| $func |= 4 }
						ida.get_function_blocks(f) { |fb| $func |= 8 if not fb.empty? }
						ida.get_xrefs_to(f) { |xr| $func |= 16 if not xr.empty?; test_flags("func", $func, 1|2|4|8|16) }
						ida.set_function_comment(f, "")
					}
				}
			}
		}
	}

	$misc = 0
	ida.get_entry(0) { |oep|
		ida.get_op_mnemonic(oep) { |op| $misc |= 1 if op }
		ida.set_comment(oep, "some entrypoint")
		ida.get_comment(oep) { |cmt| $misc |= 2 if cmt == "some entrypoint"; ida.set_comment(oep, '') }
		ida.get_flags(oep) { }
		ida.get_cpuinfo { |ci| $misc |= 4 if ci.kind_of?(::Hash) }
		ida.set_cursor_pos(oep)
		ida.get_next_head(oep) { |nh| ida.get_prev_head(nh) { |ph| $misc |= 8 if ph == oep and ph != nh } }
		ida.get_heads(oep-16, oep+16) { |lh| $misc |= 16 if lh.include?(oep) }
		ida.get_selection { }
		ida.get_input_path { $misc |= 32 }
		ida.get_next_head(oep) { |nh|
			ida.undefine(nh)
			ida.make_byte(nh)
			ida.make_array(nh, 2)
			ida.make_word(nh)
			ida.make_dword(nh)
			ida.make_qword(nh)
			ida.make_string(nh, 0, 0)
			ida.make_align(nh, 1, 1)
			ida.undefine(nh)
			ida.make_code(nh)
			ida.get_byte(nh) { |b|
				ida.patch_byte(nh, b+1)
				ida.patch_byte(nh, b)
				$misc |= 64
				test_flags("misc", $misc, 1|2|4|8|16|32|64)
			}
		}
	}
}

test_flags("nb of tests", $tests_done.length, 6)
