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

## Cracked NIDs: the version-suffixed `sceMeAudio` functions

A PSP NID is the first 4 bytes of `SHA1(name)` read little-endian. Across all
firmwares `psplibdoc.xml` lists 316 unnamed `sceMeAudio` functions under
`popsman.prx`. 25 of them are five functions whose names carry a firmware
version suffix:

| function | `""` | `v33` | `v34` | `v35` | `v352` |
|---|---|---|---|---|---|
| `sceMeAudioRegisterTickCallback` | `0x148E487D` | `0xA54D5B20` | `0xB745BA7C` | `0xA002ED78` | `0x66DA46E2` |
| `sceMeAudioSetPause`             | `0x29798EF3` | `0x745FB863` | `0x448F65DD` | `0xC044E289` | `0x5F711DD6` |
| `sceMeAudioSetVolume`            | `0xDDB5FA7A` | `0x6DCDC5BA` | `0x83E07D86` | `0x43D9752F` | `0x25F12580` |
| `sceMeAudioScLock`               | `0x5EDA8D33` | `0xEDD2B615` | `0x94DCC979` | `0xA345F290` | `0xE2ECB299` |
| `sceMeAudioScUnlock`             | `0x05115756` | `0x1AF750F2` | `0x5B571930` | `0x7EFCF769` | `0x0EEC95DF` |

The suffix is part of the **name**, not a salt bolted onto a fixed one: the
function in 3.30's popsman really is called `sceMeAudioSetVolumev33`, and
`SHA1("sceMeAudioSetVolumev33")[0:4]` is `0x6DCDC5BA`. That matters when
writing them into `psplibdoc.xml` -- entering the bare name on all five would
map one name to five NIDs and break the `SHA1(name)[0:4] == NID` invariant that
every NID tool depends on. All 25 entries as written satisfy it.

These 25 NIDs occupy 33 entries, because the un-suffixed five also appear in
`meaudio.prx` and in the `sceMeAudio_driver` libraries.

### One generation per firmware, not all of them at once

Parsing the export tables of all 11,346 decrypted PRX in a 1.00-6.61 firmware
corpus shows `popsman.prx` exports **exactly 5 `sceMeAudio` functions in any one
firmware**, and all 5 NIDs are replaced at each boundary:

    3.10, 3.11   05115756 148E487D 29798EF3 5EDA8D33 DDB5FA7A   (no suffix)
    3.30         1AF750F2 6DCDC5BA 745FB863 A54D5B20 EDD2B615   (v33)
    3.40         448F65DD 5B571930 83E07D86 94DCC979 B745BA7C   (v34)

`pops.prx` is the only importer. So the 316 figure is the **union over
firmwares** that `psplibdoc.xml` accumulates, not one module's export list --
Sony re-randomised these five functions at each release rather than shipping a
compatibility shim for every past build.

`obfuscations.csv` in [pspdev/psplibdoc](https://github.com/pspdev/psplibdoc)
independently records the same boundaries for `popsman.prx` / `sceMeAudio` --
**3.11 -> 3.30 -> 3.40 -> 3.50** and **3.51 -> 3.52**, five NIDs each:

| suffix | firmware |
|---|---|
| `""` | 3.10, 3.11 |
| `v33` | 3.30 |
| `v34` | 3.40 |
| `v35` | 3.50, 3.51 |
| `v352` | 3.52 |

Read straight off the export tables of all 43 `popsman.prx` copies in a
1.00-6.61 firmware corpus, so the set is complete rather than inferred.
`popsman.prx` exports **no** `sceMeAudio` library at all before 3.10, which is
why there is no `v30`/`v31`/`v303` generation, and 3.10/3.11 use the bare
names. From 3.70 the library jumps to 22-37 exports and none of them is any
suffixed form of these five names -- those are the randomised generations, and
all 208 of them are already in `psplibdoc.xml` as unnamed placeholders.

### 43 more NIDs, by propagation rather than by hash

`obfuscation_pairs.csv` links the same function across each boundary without
naming it. Union-find over its 48,520 pairs puts our five names in classes of
12-13 members; the 25 hash-proven NIDs above account for five each, and the
remaining **43** are the same five functions re-randomised at 3.60 and later.
These are inferred from the pair chain, not hash-proven:

| name | NIDs |
|---|---|
| `sceMeAudioRegisterTickCallback` | `0DBDA9E8` `100C3E32` `4E328267` `83FDFBC7` `8980EACE` `C45FFD6B` `D1118454` `DE630CD2` `F789CB85` |
| `sceMeAudioSetPause` | `040661A9` `2AD63E19` `3141321C` `530D2063` `6F3D46C0` `7014C540` `A77B5F0E` `D3A567AB` `D3B3005C` |
| `sceMeAudioSetVolume` | `120C8DD1` `540FC11F` `645200A3` `7DB78388` `9BB1E229` `BE3446EF` `C93C56F8` `F37154A3` `FA563F39` |
| `sceMeAudioScLock` | `0CCD56D6` `46117E79` `6D6E72C8` `A156F8A9` `C6479FE3` `D334B24A` `EA7030B9` `F6F24AFD` |
| `sceMeAudioScUnlock` | `15886ACE` `36B80978` `7BDDCF08` `BDA8AE5C` `CAFB29C5` `EE239D0A` `F4B12F84` `F4E9226C` |

### What was searched and did not pay off

Recorded so the same ground is not covered twice. All three used the same
acceptance rule: a candidate is only believed when it hits **two or more
salts**, which costs ~7e-14 per candidate and so cannot fire by accident.

| search | size | result |
|---|---|---|
| every known name x salts `v0`..`v9999`, against all 24,962 unnamed NIDs | 4.9e7 hashes | 318 raw hits vs 287 expected by chance; the only `(library, salt)` cell with more than one member is `popsman.prx/sceMeAudio`. **No other library in the collection is version-salted.** |
| `sceMeAudio` + up to three tokens from an 800-word vocabulary | 5.1e8 names | 2,962 survivors vs 2,979 expected by chance -- pure noise. Blind name generation recovers nothing. |
| every suffix up to **5** chars over `[0-9a-zA-Z._-]`, against the five known names | 5.9e9 hashes | only `""`, `v33`, `v34`, `v35`, `v352`. The 3.60+ boundaries do **not** use a short printable suffix, which is consistent with those NIDs being randomised rather than hashed. |
| for each of the 2,328 names that `psplibdoc.xml` maps to more than one NID, that name + 61,260 version-shaped suffixes (`v370`, `V370`, `_v370`, `370`, `v3.70`, ...), tested against that name's own NIDs | 1.4e8 hashes | **0**. No other library re-uses the version-suffix trick; every other duplicate name is an obfuscated NID recovered by RE, not by hash. |

The whole `psplibdoc.xml` still has 35,143 unnamed functions. The lever that
worked here was a known plaintext name plus a guessable suffix; the lever that
did not was guessing names.

## Applied to `psplibdoc.xml`

The 33 entries for the 25 hash-proven NIDs above are written into
`psplibdoc.xml` (timestamped `.bak` alongside). Every one satisfies
`SHA1(name)[0:4] == NID`. The 43 propagated NIDs are **not** applied -- they are
inferred from the pair chain, not hash-proven.

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
