def pickle_parse(rawpickle)
	# from http://formats.kaitai.io/python_pickle/
	defs_txt = <<EOD
            Mark = 40,
            EmptyTuple = 41,
            Stop = 46,
            Pop = 48,
            PopMark = 49,
            Dup = 50,
            Binbytes = 66,
            ShortBinbytes = 67,
            Float = 70,
            Binfloat = 71,
            Int = 73,
            Binint = 74,
            Binint1 = 75,
            Long = 76,
            Binint2 = 77,
            None = 78,
            Persid = 80,
            Binpersid = 81,
            Reduce = 82,
            String = 83,
            Binstring = 84,
            ShortBinstring = 85,
            Unicode = 86,
            Binunicode = 88,
            EmptyList = 93,
            Append = 97,
            Build = 98,
            Global = 99,
            Dict = 100,
            Appends = 101,
            Get = 103,
            Binget = 104,
            Inst = 105,
            LongBinget = 106,
            List = 108,
            Obj = 111,
            Put = 112,
            Binput = 113,
            LongBinput = 114,
            Setitem = 115,
            Tuple = 116,
            Setitems = 117,
            EmptyDict = 125,
            Proto = 128,
            Newobj = 129,
            Ext1 = 130,
            Ext2 = 131,
            Ext4 = 132,
            Tuple1 = 133,
            Tuple2 = 134,
            Tuple3 = 135,
            Newtrue = 136,
            Newfalse = 137,
            Long1 = 138,
            Long4 = 139,
            ShortBinunicode = 140,
            Binunicode8 = 141,
            Binbytes8 = 142,
            EmptySet = 143,
            Additems = 144,
            Frozenset = 145,
            NewobjEx = 146,
            StackGlobal = 147,
            Memoize = 148,
            Frame = 149,
EOD

	defs = {}
	defs_txt.each_line { |l|
		k, v = l.chomp(',').split('=')
		defs[v.strip.to_i] = k.strip
	}

	i = 0
	readn = lambda { |n|
		raw = rawpickle[i, n]
		i += n
		raw
	}
	readb = lambda { readn[1].unpack('C').first }
	readV = lambda { readn[4].unpack('V').first }
	readnl = lambda { readn[rawpickle.index("\n", i) - i + 1].chomp }

	stk = []
	markpos = []
	memo = {}
	popmark = lambda { out = stk[markpos.last..-1] ; stk[markpos.pop..-1] = [] ; out }
	popn = lambda { |n| out = stk[-n..-1] ; stk[-n..-1] = [] ; out }

	while i < rawpickle.length
		curop = readb[]
		curdef = defs[curop]
		if $DEBUG
			print "#{curdef || curop.inspect} "
		end

		v = :canary	# allow false/nil to be detected
		case curdef
		when 'Append', 'Appends'
			val = (curdef == 'Append' ? stk.pop : popmark[])
			v = obj = stk.pop
			if obj.kind_of?(::Array) and obj.first.kind_of?(::Symbol)
				v = [:append, obj, val]
			elsif obj.kind_of?(::Array)
				obj.append(val)
			else
				puts "append to #{obj.inspect} val #{val.inspect}"
				break
			end
		when 'Binfloat'
			v = readn[8].unpack('D').first
		when 'Binget'
			idx = readb[]
			print "#{idx} " if $DEBUG
			v = memo[idx]
		when 'Binint'
			v = readV[]
		when 'Binint1'
			v = readb[]
		when 'Binint2'
			v = (readb[] << 8) | readb[]
		when 'Binput'
			idx = readb[]
			print "#{idx} " if $DEBUG
			memo[idx] = stk.last
		when 'Binunicode'
			l = readV[]
			v = readn[l]
		when 'Binstring'
			l = readV[]
			v = readn[l]
		when 'Build'
			stk.pop	# set internal obj attributes to top of stack depending on state?
			# TODO setitem-like
		when 'EmptyDict'
			v = {}
		when 'EmptyList'
			v = []
		when 'EmptyTuple'
			v = []
		when 'Global'
			v = [:global, readnl[], readnl[]]	# return a class reference (module.class)
		when 'Long1'
			l = readb[]
			v = readn[l]
		when 'LongBinput'
			idx = readV[]
			print "#{idx} " if $DEBUG
			memo[idx] = stk.last
		when 'LongBinget'
			idx = readV[]
			print "#{idx} " if $DEBUG
			v = memo[idx]
		when 'Mark'
			markpos << stk.length
		when 'Newobj'
			v = [:newobj] + popn[2]
		when 'Newtrue'
			v = true
		when 'Newfalse'
			v = false
		when 'None'
			v = nil
		when 'Proto'
			v = readb[]
			print v if $DEBUG
			v = nil
		when 'Reduce'
			v = [:reduce] + popn[2]	# funcname, argtuple
		when 'Setitem'
			elems = popn[2]
			h = { elems[0] => elems[1] }
			v = stk.pop
			if v.kind_of?(::Array) and v.first.kind_of?(::Symbol)
				if v[0] == :setitem
					v[-1].update h
				else
					v = [:setitem, v, h]
				end
			elsif v.kind_of?(::Hash)
				v.update h
			else
				raise "Setitem with not hash but #{v.inspect} #{elems.inspect}" if not v.kind_of?(::Hash)
			end
		when 'Setitems'
			elems = popmark[]
			h = {}
			while elems.length > 0
				h[elems.shift] = elems.shift
			end
			v = stk.pop
			if v.kind_of?(::Array) and v.first.kind_of?(::Symbol)
				if v[0] == :setitem
					v[-1].update h
				else
					v = [:setitem, v, h]
				end
			elsif v.kind_of?(::Hash)
				v.update h
			else
				raise "Setitem with not hash but #{v.inspect} #{elems.inspect}" if not v.kind_of?(::Hash)
			end
		when 'ShortBinstring'
			l = readb[]
			v = readn[l]
		when 'Stop'
			# EOF
			# TODO return pop[] ?
		when 'Tuple1'
			v = popn[1]
		when 'Tuple2'
			v = popn[2]
		when 'Tuple3'
			v = popn[3]
		when 'Tuple'
			v = popmark[]
		else
			puts "Unhandled pickle op #{curop.inspect} #{curdef.inspect} #{readn[16].inspect}"
			break
		end
		stk << v if v != :canary

		if $DEBUG
			if v != :canary
				p v
			else
				puts
			end
		end
	end

	#p markpos
	#p stk
	stk
end

if __FILE__ == $0
	pickled = File.open(ARGV.shift, 'rb') { |fd| fd.read }
	pp pickle_parse(pickled)	
end
