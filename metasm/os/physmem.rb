#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/os/main'

module Metasm

# This class implements a virtual memory mapper for x86 64-bit paging
# wraps another virtualstring that acts as the physical memory backing
class PhysMemX64 < VirtualString
	# create a new virtual mapping from a physical dump file
	def self.read(path, cr3=0)
		raise 'no filename specified' if not path
		new(VirtualFile.read(path), cr3)
	end

	attr_accessor :physmem, :cr3, :paging_level
	# create a new virtual mapping from a physical memory raw buffer
	def initialize(physmem, cr3=0, addr_start=0, length=1<<64, paging_level=4)
		@physmem = physmem
		@cr3 = cr3
		@paging_level = paging_level
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@physmem, @cr3, addr, len, @paging_level)
	end

	PAGE_ADDR_MASK = 0x01ff_ffff_ffff_f000
	def get_page_aligned(addr)
		case @paging_level
		when 5
			pml5 = @cr3 & PAGE_ADDR_MASK
			pml5e = @physmem[pml5 + ((addr >> 48) & 0x1ff) * 8, 8].unpack('Q').first
			return if pml5e & 0 == 0	# page present
			if pml5e & 0x80 == 0x80
				# hugest page
				return @physmem[(pml5e & PAGE_ADDR_MASK & ~0xffff_ffff_f000) | (addr & 0xffff_ffff_f000), 4096]
			end
		when 4
			pml5e = @cr3
		else
			raise 'paging level unsupported'
		end

		pml4 = pml5e & PAGE_ADDR_MASK
		pml4e = @physmem[pml4 + ((addr >> 39) & 0x1ff) * 8, 8].unpack('Q').first
		return if pml4e & 1 == 0	# page not present
		if pml4e & 0x80 == 0x80
			# huger page
			return @physmem[(pml4e & PAGE_ADDR_MASK & ~0x7f_ffff_f000) | (addr & 0x7f_ffff_f000), 4096]
		end

		pdpt = pml4e & PAGE_ADDR_MASK
		pdpe = @physmem[pdpt + ((addr >> 30) & 0x1ff) * 8, 8].unpack('Q').first
		return if pdpe & 1 == 0
		if pdpe & 0x80 == 0x80
			# huge page
			return @physmem[(pdpe & PAGE_ADDR_MASK & ~0x3fff_f000) | (addr & 0x3fff_f000), 4096]
		end

		pdt = pdpe & PAGE_ADDR_MASK
		pde = @physmem[pdt + ((addr >> 21) & 0x1ff) * 8, 8].unpack('Q').first
		return if pde & 1 == 0
		if pde & 0x80 == 0x80
			# large page
			return @physmem[(pde & PAGE_ADDR_MASK & ~0x1f_f000) | (addr & 0x1f_f000), 4096]
		end

		pt = pde & PAGE_ADDR_MASK
		pte = @physmem[pt + ((addr >> 12) & 0x1ff) * 8, 8].unpack('Q').first
		return if pte & 1 == 0

		return @physmem[pte & PAGE_ADDR_MASK, 4096]
	end

	# return at most one page
	def get_page(addr, len=@pagelength)
		addr_off = addr & 0xfff
		pg = get_page_aligned(addr & 0xffff_ffff_ffff_f000)
		len = 4096-addr_off if len > 4096-addr_off
		pg[addr_off, len] if pg
	end
end
end
