# prxldr for IDA Pro 9.4

IDAPython port of [xyzz/prxldr](https://github.com/xyzz/prxldr), the PSP PRX
loader written against the IDA 6.1 C SDK (itself derived from prxtool).

## Why Python and not a rebuilt C plugin

The original is a `.ldw` built from `prxldr.c` against `../idaldr.h`. Rebuilding
it for 9.4 would need the IDA 9.4 SDK plus MSVC, neither of which is installed
here, and the SDK API it uses is gone anyway: `doDwrd`, `doASCI`, `get_long`,
`put_long`, `get_many_bytes`, `askaddr`, `askfile_c`, `describe`, the `ph.id`
global and the `loader_t LDSC` block were all renamed or removed across 6.x ->
7.0 -> 9.x. A Python loader needs no SDK and no compiler.

## Install

    copy prxldr.py  C:\ida94b1\loaders\

(already done). Optionally put a `psplibdoc.xml` in the same directory --
`C:\ida94b1\loaders\psplibdoc.xml` is already present on this machine and is
picked up automatically.

IDA's own ELF loader also recognises PSP PRX files, so on opening a `.prx` you
get a loader-choice dialog; pick **PSP PRX Loader**. From the command line:

    idat.exe -A -B "-TPSP PRX Loader" file.prx

## What it does

Same as the original:

* accepts ELF32/MIPS/LE with `e_type == 0xFFA0` or the Allegrex machine flag
* selects the `psp` processor variant (falls back to `mipsl`)
* asks for a relocation base when `e_entry < 0x08800000` (default `0x08804000`)
* maps sections when a section table is present, program headers otherwise
* creates `.bss` from the last `PT_LOAD`'s `p_memsz - p_filesz`
* decodes type-A relocations (`SHT_PRXRELOC` / `SHT_REL` / `PT_PRXRELOC`) and
  the packed `PT_PRXRELOC2` format, then applies `R_MIPS_16/32/26/HI16/LO16`
  and the PSP-specific `R_MIPS_X_HI16/X_J26/X_JAL26`
* parses `.rodata.sceModuleInfo` (or `phdr[0].p_paddr` when there is no
  section table) and names every field
* walks the export and import stubs, naming each entry from `psplibdoc.xml`
  or the built-in `syslib` / `sceLibc` / `sceLibm` tables (688 NIDs, generated
  from the original `scelibnids.c`), falling back to `libname_nnnnnnnn`

## Deliberate differences from the C original

| | |
|---|---|
| `count_relocs()` dropped | it only sized a fixed array; its private copy of the PRXRELOC2 decoder had `pos[1] << 16` (should be `<< 8`) and `part1 & 0x38 == 0x10` (parses as `part1 & (0x38 == 0x10)`), so it could undersize that array |
| zero-size `.bss` no longer fatal | `create32()` called `loader_failure()` when `add_segm(s, s)` failed |
| `force_name()` instead of `set_name()` | NIDs repeat across libraries; the original silently dropped every colliding name |
| HI16 fixup bounds-checked | the C loop read one `ElfReloc` past the end of its array |
| `psplibdoc.xml` parsed with ElementTree | with the original flat `strstr()` scan kept as a fallback; cancelling the file prompt no longer matters |
| `$gp` is set | read *after* relocation from `_module_gp` (gp usually relocates against the data segment, so `modinfo.gp + base` is the wrong value), applied to every segment as the MIPS `gp` **segment** register -- note `str2reg("gp")` returns GPR 28, not the sreg |
| `module_start` entry point added | so IDA has a seed for analysis |

The list linked-list bugs in `load_single_export`/`load_single_import`
(`pExport = prx->plibexp = pLib;`, `memset(pLib, 0, sizeof(PspModuleImport))`
on a `PspLibImport`) are gone by construction.

## Verified on

`umdman.prx` (sceUmdMan_driver, 129,592 bytes, 25 sections, 7 `SHT_PRXRELOC`
sections):

* 14 segments, image `08804000-0881DC78`
* 3398 relocations applied
* 611 names; 2 export libs (`syslib`, `sceUmdMan_driver`), 14 import libs
* **0 unresolved NID placeholders**
* 2134 `jal`/`j` targets in range, 0 out of range
* 509/509 HI16+LO16 pairs resolve to addresses inside the image, e.g.
  `lui $a1, 0x881 / addiu $a0, $a1, (sceUmdManMediaPresent - 0x8810000)`
* `$gp = 0x08824790` (relocated against `phdr[1]`, not `phdr[0]`)

plus two synthetic PRX files exercising the section-table path and the
program-header-only path (`PT_PRXRELOC` + `p_paddr` module-info fallback).
