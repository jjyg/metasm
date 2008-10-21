#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
# a class representing a structure serialized in a binary
# TODO handle bitfields in an int
class SerialStruct
	# hash shared by all classes
	# key = class, value = array of fields
	# field = array [name, decode...]
	@@fields = {}
	NAME=0
	DECODE=1
	ENCODE=2
	DEFVAL=3
	ENUM=4
	BITS=5

	class << self
	# define a new field
	# adds an accessor
	def new_field(name, decode, encode, defval, enum=nil, bits=nil)
		attr_accessor name
		name = "@#{name}".to_sym
		(@@fields[self] ||= []) << [name, decode, encode, defval, enum, bits]
	end

	# creates a field constructor for a simple integer
	# relies on exe implementing (en,de)code_#{type}
	Struct_new_inttype = proc { |*fldtype|
		fldtype.each { |ftype|
		 define_method(ftype) { |name, *args|
			args[0] ||= 0
			new_field(name, "decode_#{ftype}".to_sym, "encode_#{ftype}".to_sym, args[0], args[1])
		 }
		 # shortcut to define multiple fields of this type with default values
		 define_method("#{ftype}s".to_sym) { |*names|
			names.each { |name|
				send ftype, name
			}
		 }
		}
	}

	Struct_new_inttype[:byte, :half, :word]

	# a fixed-size memory chunk
	def mem(name, len, defval='')
		new_field(name, proc { |exe, me| exe.encoded.read(len) }, proc { |exe, me, val| val[0, len].ljust(len, 0.chr) }, defval)
	end
	# a fixed-size string, 0-padded
	def str(name, len, defval='')
		e = proc { |exe, me, val| val[0, len].ljust(len, 0.chr) }
		d = proc { |exe, me| v = exe.encoded.read(len) ; v = v[0, v.index(0)] if v.index(0) ; v }
		new_field(name, d, e, defval)
       	end
	# 0-terminated string
	def strz(name, defval='')
		d = proc { |exe, me|
		       	ed = exe.encoded
			ed.read(ed.data.index(0, ed.ptr)+1).chop
		}
		new_field(name, d, proc { |exe, me, val| val + 0.chr }, defval)
	end

	def fld_get(name)
		name = "@#{name}".to_sym
		@@fields[self].find { |f| f[NAME] == name }
	end

	# change the default for a field
	def fld_default(name, default=nil, &b)
		default ||= b
		fld_get(name)[DEFVAL] = default
	end
	def fld_enum(name, enum=nil, &b) fld_get(name)[ENUM] = enum||b end
	def fld_bits(name, bits=nil, &b) fld_get(name)[BITS] = bits||b end

	# inject a hook to be run during the decoding process
	def decode_hook(&b)
		@@fields[self] << [nil, b]
	end

	end

	# returns this classes' field array
	def struct_fields() @@fields[self.class].to_a end

	# decodes the fields from the exe
	def decode(exe)
		struct_fields.each { |f|
			case d = f[DECODE]
  			when Symbol; val = exe.send(d)
			when Array; val = exe.send(*d)
			when Proc; val = d[exe, self]
			when nil; next
			end
			next if not f[NAME]
			if h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = exe.int_to_hash( val, h) end
			if h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = exe.bits_to_hash(val, h) end
			instance_variable_set(f[NAME], val)
		}
	end
	def set_default_values(exe)
		struct_fields.each { |f|
			next if not f[NAME]
			next if instance_variables.map { |ivn| ivn.to_sym }.include?(f[NAME]) and instance_variable_get(f[NAME])
			val = f[DEFVAL]
			val = val[exe, self] if val.kind_of? Proc
			if val.kind_of? Integer and h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = exe.int_to_hash( val, h) end
			if val.kind_of? Integer and h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = exe.bits_to_hash(val, h) end
			instance_variable_set(f[NAME], val)
		}
	end
	# sets default values, then encodes the fields, returns an EData
	def encode(exe, *a)
		set_default_values(exe, *a)

		struct_fields.inject(EncodedData.new) { |ed, f|
			if not f[NAME]
				f[ENCODE][exe, self, nil] if f[ENCODE]
				next ed
			end
			val = instance_variable_get(f[NAME])
			if h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = exe.int_from_hash( val, h) end
			if h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = exe.bits_from_hash(val, h) end
			case e = f[ENCODE]
			when Symbol; val = exe.send(e, val)
			when Array; val = exe.send(e, *val)
			when Proc; val = e[exe, self, val]
			when nil; val = nil
			end
			ed << val
		}
	end

	def self.decode(*a)
		s = new
		s.decode(*a)
		s
	end

	def to_s
		# use fields display order
		ivs = instance_variables.map { |iv| iv.to_sym }
		ivs = (struct_fields.map { |f| f[NAME] }.compact & ivs) | ivs
		"<#{self.class} " + ivs.map { |iv|
			v = instance_variable_get(iv)
			case v
			when Integer; v = '0x%X'%v if v >= 0x100
			when String; v = v[0, 64].inspect + (v.length > 64 ? '...' : '')
			# TODO when EncodedData
			else v = v.inspect
			end
		       	"#{iv}=#{v}"
		}.join(' ') + ">"
	end

	# create a new instance of otherclass and copy all instance variables to it
	# useful for specialized subclasses (eg ELF::Symbol{32,64}), where you
	# have an object and don't known which subclass to cast it to until late in
	# the encoding process (eg where cpu.size is set)
	def clone_to(otherclass)
		other = otherclass.allocate
		instance_variables.each { |iv|
			other.instance_variable_set(iv, instance_variable_get(iv))
		}
		other
	end
end
end
