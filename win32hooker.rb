require 'metasm'

require 'dl'
require 'dl/import'
require 'dl/struct'

module Psapi
	extend DL::Importable
	dlload 'psapi'

	extern 'int EnumProcesses(long*, long, long*)'
end
module Kernel32
	extend DL::Importable
	dlload 'kernel32'

	extern ''
end

def enum_processes
	list = DL.malloc(4096)
	len = DL.malloc(DL.sizeof('i'))
	len.struct!('I', 'len')
	len['len'] = 0
	ret = Psapi::enumProcesses(list, 4096, len)
	puts "response: #{ret}, ary len #{len['len']}"
end

enum_processes
