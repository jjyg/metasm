#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


Metasmdir = File.dirname(__FILE__)

module Metasm

def const_missing(c) Metasm.const_missing(c) end
def self.const_missing(c)
	# constant defined in the same file as another
	cst = {
		'X86' => 'Ia32', 'PPC' => 'PowerPC',
		'UniversalBinary' => 'MachO', 'COFFArchive' => 'COFF',
		'PTrace32' => 'LinOS', 'GNUExports' => 'LinOS',
		'LinuxRemoteString' => 'LinOS',
		'WinAPI' => 'WinOS', 'WindowsExports' => 'WinOS',
		'WindowsRemoteString' => 'WinOS', 'WinDbg' => 'WinOS',
		'VirtualFile' => 'OS', 'VirtualString' => 'OS',
		'EncodedData' => 'Expression',
	}[c.to_s] || c.to_s

	files = {
		'Ia32' => 'ia32', 'MIPS' => 'mips', 'PowerPC' => 'ppc',
		'C' => ['parse_c', 'compile_c'],
		'MZ' => 'exe_format/mz', 'PE' => 'exe_format/pe',
		'ELF' => ['exe_format/elf_encode', 'exe_format/elf_decode'],
		'COFF' => ['exe_format/coff_encode', 'exe_format/coff_decode'],
		'Shellcode' => 'exe_format/shellcode', 'AutoExe' => 'exe_format/autoexe',
		'AOut' => 'exe_format/a_out', 'MachO' => 'exe_format/macho',
		'NDS' => 'exe_format/nds', 'XCoff' => 'exe_format/xcoff',
		'GtkGui' => 'gui/gtk',
		'OS' => 'os/main',
		'LinOS' => 'os/linux', 'WinOS' => 'os/windows',
		'Disassembler' => 'decode', 'Expression' => ['main', 'encode', 'decode'],
	}[cst]

	return super if not files	# XXX does it work if another module included defines const_missing?

	files = [files] if files.kind_of? ::String

	# temporarily put the current file directory in the ruby include path
	if not $:.include? Metasmdir
		incdir = Metasmdir
		$: << incdir
	end
	files.each { |f| require File.join('metasm', f) }
	$:.delete incdir if incdir

	const_get c
end

# without this, include Metasm => const_missing magick doesn't work anymore
# this will probably break x.const_missing..
def self.included(x)
	x.class_eval 'def self.const_missing(c) Metasm.const_missing(c) end'
end
end
