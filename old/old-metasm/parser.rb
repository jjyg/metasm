module Metasm

def Label.parse(s)
	Label.new(s.chop, nil) if s[-1] == ?:
end

def Data.parse(str)
	case str
	when /^db (.*)$/
	when /^db\? (.*)$/
	end
end

def Immediate.parse(str)
	case str
	when /^(-?0[xX][0-9a-fA-F]+)$/, /^(-?[0-9a-fA-F]+)h$/
		$1.hex
	when /^(-?0[0-9]+)$/
		$1.oct
	when /^(-?[0-9]+)$/
		$1.to_i
	# else ; nil
	end
end

end
