/* One read-execute segment holding the headers, as the kernel lays out its
   vDSO: no writable .dynamic, nothing to relocate. */
SECTIONS {
	. = SIZEOF_HEADERS;
	.hash : { *(.hash) } :text
	.gnu.hash : { *(.gnu.hash) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }
	.gnu.version : { *(.gnu.version) }
	.gnu.version_d : { *(.gnu.version_d) }
	.gnu.version_r : { *(.gnu.version_r) }
	.dynamic : { *(.dynamic) } :text :dynamic
	.rodata : { *(.rodata*) } :text
	.text : { *(.text*) } :text
	/DISCARD/ : { *(.note.GNU-stack) *(.data*) *(.bss*) *(.eh_frame*) *(.comment) }
}
PHDRS {
	text PT_LOAD FLAGS(5) FILEHDR PHDRS;
	dynamic PT_DYNAMIC FLAGS(4);
}
