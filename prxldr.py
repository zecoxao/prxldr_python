# -*- coding: utf-8 -*-
"""
PSP PRX loader for IDA Pro 9.x  (developed/tested against IDA Pro 9.4)

IDAPython port of https://github.com/xyzz/prxldr -- a C loader written against
the IDA 6.1 SDK, itself derived from prxtool.  Behaviour is kept the same as
the original: same segment layout, the same PT_PRXRELOC / PT_PRXRELOC2
relocation decoder, the same import/export walker, and the same NID -> name
resolution (psplibdoc.xml plus the built-in sceLibc / sceLibm / syslib tables
that shipped in scelibnids.c).

Install: copy this file into <IDADIR>/loaders/ .

Optional: drop a psplibdoc.xml next to it (or into <IDADIR>/cfg/) to get real
function names instead of "sceCtrl_6D4E9A47" style placeholders.  If it is not
found you are asked for it once; cancelling is fine, loading just continues
with placeholder names.
"""

import os
import re
import struct

import ida_bytes
import ida_diskio
import ida_entry
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_segregs

# ---------------------------------------------------------------------------
# constants (prxldr.h)
# ---------------------------------------------------------------------------

ELF_MAGIC = 0x464C457F
EI_CLASS, ELFCLASS32 = 4, 1
EI_DATA, ELFDATA2LSB = 5, 1
EM_MIPS = 8
ET_PRX = 0xFFA0

E_MIPS_MACH_ALLEGREX = 0x00A20000
EF_MIPS_MACH = 0x00FF0000
EBOOT_BASE_ADDR = 0x08800000 + 0x4000

PT_LOAD = 1
PT_PRXRELOC = 0x700000A0
PT_PRXRELOC2 = 0x700000A1

PF_X = 1

SHT_PROGBITS = 1
SHT_REL = 9
SHT_LOPROC = 0x70000000
SHT_PRXRELOC = SHT_LOPROC | 0xA0

SHF_ALLOC = 1 << 1
SHF_EXECINSTR = 1 << 2

R_MIPS_NONE = 0
R_MIPS_16 = 1
R_MIPS_32 = 2
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6
R_MIPS_X_HI16 = 13
R_MIPS_X_J26 = 14
R_MIPS_X_JAL26 = 15

PSP_MODULE_INFO_NAME = ".rodata.sceModuleInfo"
PSP_MODULE_MAX_NAME = 28
PSP_LIB_MAX_NAME = 128
PSP_SYSTEM_EXPORT = "syslib"
PSP_IMPORT_BASE_SIZE = 5 * 4

EHDR = struct.Struct("<16sHHIIIIIHHHHHH")   # 52
SHDR = struct.Struct("<10I")                # 40
PHDR = struct.Struct("<8I")                 # 32
REL = struct.Struct("<2I")                  # 8
MODINFO = struct.Struct("<I28s5I")          # 52

# field offsets inside the on-disk structures, used when naming their fields
MI_FLAGS, MI_NAME, MI_GP = 0, 4, 32
MI_EXPORTS, MI_EXP_END, MI_IMPORTS, MI_IMP_END = 36, 40, 44, 48

EXP_NAME, EXP_FLAGS, EXP_COUNTS, EXP_EXPORTS = 0, 4, 8, 12
IMP_NAME, IMP_FLAGS, IMP_COUNTS = 0, 4, 8
IMP_NIDS, IMP_FUNCS, IMP_VARS = 12, 16, 20

MASK32 = 0xFFFFFFFF


def u32(x):
    return x & MASK32


def s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def s32(x):
    x &= MASK32
    return x - 0x100000000 if x & 0x80000000 else x


def msg(fmt, *args):
    text = (fmt % args) if args else fmt
    ida_kernwin.msg("[prxldr] " + text + "\n")


# ---------------------------------------------------------------------------
# small IDA helpers (SDK 6.1 name -> 9.x name)
# ---------------------------------------------------------------------------

def make_dword(ea):
    """doDwrd(ea, 4)"""
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    ida_bytes.create_dword(ea, 4, True)


def make_string(ea, length=0):
    """doASCI(ea, len); length 0 == auto"""
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(length, 1))
    ida_bytes.create_strlit(ea, length, ida_nalt.STRTYPE_C)


def name_ea(ea, name):
    """set_name().  force_name() is used instead so that NIDs repeating across
    libraries do not silently lose their name, as they did in the original."""
    ida_name.force_name(ea, name, ida_name.SN_NOCHECK)


def get_dword(ea):
    return ida_bytes.get_dword(ea)


def put_dword(ea, val):
    ida_bytes.put_dword(ea, u32(val))


def read_cstr(ea, maxlen=PSP_LIB_MAX_NAME):
    raw = ida_bytes.get_bytes(ea, maxlen)
    if not raw:
        return ""
    return raw.split(b"\x00")[0].decode("latin-1")


def read_cstr_buf(buf, off):
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("latin-1")


def create32(start, end, name, sclass):
    """create32() from the original, minus the loader_failure() on a zero-size
    segment (the original aborted the whole load on a PRX with an empty .bss)"""
    if end <= start:
        return None
    if not ida_segment.add_segm(0, start, end, name, sclass):
        ida_loader.loader_failure("cannot create segment %s at %08X"
                                  % (name, start))
    seg = ida_segment.getseg(start)
    if seg is not None:
        ida_segment.set_segm_addressing(seg, 1)
    return seg


# ---------------------------------------------------------------------------
# PRX container
# ---------------------------------------------------------------------------

class PrxInfo(object):
    def __init__(self, buf):
        self.buf = buf
        self.size = len(buf)
        self.ehdr = None
        self.shdr = []
        self.phdr = []
        self.secname = []
        self.relocs = []
        self.modinfo = None                  # parsed PspModuleInfo
        self.modinfo_ea = ida_idaapi.BADADDR
        self.nids = {}                       # libname -> {nid: name}


def parse_ehdr(buf):
    f = EHDR.unpack_from(buf, 0)
    return dict(e_ident=f[0], e_type=f[1], e_machine=f[2], e_version=f[3],
                e_entry=f[4], e_phoff=f[5], e_shoff=f[6], e_flags=f[7],
                e_ehsize=f[8], e_phentsize=f[9], e_phnum=f[10],
                e_shentsize=f[11], e_shnum=f[12], e_shstrndx=f[13])


def is_prx(li):
    li.seek(0)
    data = li.read(EHDR.size)
    if not data or len(data) < EHDR.size:
        return False
    e = parse_ehdr(data)
    if struct.unpack_from("<I", e["e_ident"], 0)[0] != ELF_MAGIC:
        return False
    if (e["e_ident"][EI_DATA] != ELFDATA2LSB
            or e["e_ident"][EI_CLASS] != ELFCLASS32
            or e["e_machine"] != EM_MIPS):
        return False
    if e["e_type"] == ET_PRX:
        return True
    if (e["e_flags"] & EF_MIPS_MACH) == E_MIPS_MACH_ALLEGREX:
        return True
    return False


def find_section(prx, name):
    for i, n in enumerate(prx.secname):
        if n == name:
            return i
    return -1


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------

def load_section_headers(prx):
    e = prx.ehdr
    sht_size = e["e_shnum"] * e["e_shentsize"]
    if e["e_shnum"] == 0 or e["e_shoff"] + sht_size > prx.size:
        if e["e_shnum"]:
            msg("Invalid section table! ignore it.")
        e["e_shnum"] = 0
        e["e_shoff"] = 0
        e["e_shstrndx"] = 0
        return -1

    off = e["e_shoff"]
    for _ in range(e["e_shnum"]):
        f = SHDR.unpack_from(prx.buf, off)
        prx.shdr.append(dict(sh_name=f[0], sh_type=f[1], sh_flags=f[2],
                             sh_addr=f[3], sh_offset=f[4], sh_size=f[5],
                             sh_link=f[6], sh_info=f[7], sh_addralign=f[8],
                             sh_entsize=f[9]))
        off += SHDR.size

    prx.secname = [""] * e["e_shnum"]
    if 0 < e["e_shstrndx"] < e["e_shnum"]:
        strtab = prx.shdr[e["e_shstrndx"]]["sh_offset"]
        for i, sh in enumerate(prx.shdr):
            prx.secname[i] = read_cstr_buf(prx.buf, strtab + sh["sh_name"])
    return e["e_shnum"]


def load_program_headers(prx):
    e = prx.ehdr
    off = e["e_phoff"]
    if e["e_phnum"] and off + e["e_phnum"] * PHDR.size > prx.size:
        msg("[ERRO] Invalid program header table")
        return -1
    for _ in range(e["e_phnum"]):
        f = PHDR.unpack_from(prx.buf, off)
        prx.phdr.append(dict(p_type=f[0], p_offset=f[1], p_vaddr=f[2],
                             p_paddr=f[3], p_filesz=f[4], p_memsz=f[5],
                             p_flags=f[6], p_align=f[7]))
        off += PHDR.size
    return e["e_phnum"]


# ---------------------------------------------------------------------------
# segments
# ---------------------------------------------------------------------------

def load_sections(li, prx, base):
    n = 0
    for i, sh in enumerate(prx.shdr):
        if i == 0:
            continue
        if sh["sh_type"] != SHT_PROGBITS or sh["sh_size"] == 0:
            continue
        if not (sh["sh_flags"] & SHF_ALLOC):
            continue
        start = sh["sh_addr"] + base
        end = start + sh["sh_size"]
        li.file2base(sh["sh_offset"], start, end,
                     ida_loader.FILEREG_NOTPATCHABLE)
        is_code = bool(sh["sh_flags"] & SHF_EXECINSTR)
        create32(start, end, prx.secname[i] or (".seg%d" % i),
                 "CODE" if is_code else "DATA")
        n += 1
    return n


def load_programs(li, prx, base):
    n = 0
    for ph in prx.phdr:
        if ph["p_type"] != PT_LOAD or ph["p_filesz"] == 0:
            continue
        start = ph["p_vaddr"] + base
        end = start + ph["p_filesz"]
        li.file2base(ph["p_offset"], start, end,
                     ida_loader.FILEREG_NOTPATCHABLE)
        is_code = bool(ph["p_flags"] & PF_X)
        create32(start, end, ".text" if is_code else ".data",
                 "CODE" if is_code else "DATA")
        n += 1
    return n


def create_bss(prx, base):
    bss_addr = bss_size = 0
    for ph in prx.phdr:
        if ph["p_type"] == PT_LOAD:
            # as in the original: the *last* PT_LOAD wins
            bss_size = ph["p_memsz"] - ph["p_filesz"]
            bss_addr = ph["p_vaddr"] + ph["p_filesz"]
    if bss_size <= 0:
        return
    create32(bss_addr + base, bss_addr + base + bss_size, ".bss", "BSS")


# ---------------------------------------------------------------------------
# relocations
# ---------------------------------------------------------------------------

def load_relocs(prx):
    """Port of count_relocs() + load_relocs().  The counting pass is gone: it
    only existed to size a fixed array, and its private copy of the
    PT_PRXRELOC2 decoder had two bugs (`pos[1] << 16` instead of `<< 8`, and
    `part1 & 0x38 == 0x10` parsing as `part1 & (0x38 == 0x10)`) that could
    undersize that array."""
    buf = prx.buf
    relocs = []
    typea_from_section = False

    # --- type A, from sections -------------------------------------------
    for sh in prx.shdr:
        if sh["sh_type"] not in (SHT_PRXRELOC, SHT_REL):
            continue
        if sh["sh_size"] % REL.size:
            msg("[ERRO] Relocation section size invalid")
        count = sh["sh_size"] // REL.size
        if count:
            typea_from_section = True
        off = sh["sh_offset"]
        for _ in range(count):
            r_offset, r_info = REL.unpack_from(buf, off)
            relocs.append(dict(type=r_info & 0xFF, symbol=r_info >> 8,
                               offset=r_offset, base=0))
            off += REL.size
    if relocs:
        msg("Relocation entries in sections cnt [%d]", len(relocs))

    # --- from program headers --------------------------------------------
    for iprog, ph in enumerate(prx.phdr):
        if ph["p_type"] == PT_PRXRELOC:
            if typea_from_section:
                continue
            if ph["p_filesz"] % REL.size:
                msg("[ERRO] Relocation section size invalid")
            off = ph["p_offset"]
            for _ in range(ph["p_filesz"] // REL.size):
                r_offset, r_info = REL.unpack_from(buf, off)
                relocs.append(dict(type=r_info & 0xFF, symbol=r_info >> 8,
                                   offset=r_offset, base=0))
                off += REL.size

        elif ph["p_type"] == PT_PRXRELOC2:
            if decode_prxreloc2(prx, iprog, relocs) < 0:
                break

    msg("Relocation entries total cnt [%d]", len(relocs))
    return relocs


def decode_prxreloc2(prx, iprog, relocs):
    buf = prx.buf
    ph = prx.phdr[iprog]
    p = ph["p_offset"]
    end = p + ph["p_filesz"]
    if end > len(buf):
        msg("[ERRO] PT_PRXRELOC2 runs past end of file")
        return -1

    if struct.unpack_from("<H", buf, p)[0] != 0:
        msg("[ERRO] PT_PRXRELOC2 programs should start with 0x00 0x00")
        return -1

    part1s = buf[p + 2]
    part2s = buf[p + 3]
    block1 = p + 4
    block1s = buf[block1]
    block2 = block1 + block1s
    block2s = buf[block2]
    pos = block2 + block2s

    nbits = 1
    while (1 << nbits) < iprog:
        nbits += 1
        if nbits >= 33:
            msg("[ERRO] Invalid nbits")
            return -1

    offset = 0
    addend = 0
    ofsbase = 0xFFFFFFFF
    lastpart2 = block2s
    added = 0

    while pos < end:
        cmd = buf[pos] | (buf[pos + 1] << 8)
        pos += 2
        temp1 = (cmd << (16 - part1s)) & 0xFFFF
        temp1 = (temp1 >> (16 - part1s)) & 0xFFFF
        if temp1 >= block1s:
            msg("[ERRO] Invalid part1 index")
            return -1
        part1 = buf[block1 + temp1]

        if (part1 & 0x01) == 0:
            ofsbase = (cmd << (16 - part1s - nbits)) & 0xFFFF
            ofsbase = (ofsbase >> (16 - nbits)) & 0xFFFF
            if not ofsbase < iprog:
                msg("[ERRO] Invalid offset base")
                return -1
            if (part1 & 0x06) == 0:
                offset = cmd >> (part1s + nbits)
            elif (part1 & 0x06) == 4:
                offset = struct.unpack_from("<I", buf, pos)[0]
                pos += 4
            else:
                msg("[ERRO] Invalid size")
                return -1
            continue

        temp2 = (cmd << (16 - (part1s + nbits + part2s))) & 0xFFFF
        temp2 = (temp2 >> (16 - part2s)) & 0xFFFF
        if temp2 >= block2s:
            msg("[ERRO] Invalid part2 index")
            return -1
        addrbase = (cmd << (16 - part1s - nbits)) & 0xFFFF
        addrbase = (addrbase >> (16 - nbits)) & 0xFFFF
        if not addrbase < iprog:
            msg("[ERRO] Invalid address base")
            return -1
        part2 = buf[block2 + temp2]

        size = part1 & 0x06
        if size == 0:
            t = cmd
            if t & 0x8000:
                t = u32(t | ~0xFFFF)
                t >>= part1s + part2s + nbits
                t = u32(t | ~0xFFFF)
            else:
                t >>= part1s + part2s + nbits
            offset = u32(offset + t)
        elif size == 2:
            t = cmd
            if t & 0x8000:
                t = u32(t | ~0xFFFF)
            t = u32((t >> (part1s + part2s + nbits)) << 16)
            t |= buf[pos] | (buf[pos + 1] << 8)
            offset = u32(offset + t)
            pos += 2
        elif size == 4:
            offset = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        else:
            msg("[ERRO] invalid part1 size")
            return -1

        if ofsbase >= len(prx.phdr) or not offset < prx.phdr[ofsbase]["p_filesz"]:
            msg("[ERRO] invalid relocation offset")
            msg(" reloc %4d: offset=%08x ofsbase=%d", len(relocs), offset,
                ofsbase)
            return -1

        add = part1 & 0x38
        if add == 0x00:
            addend = 0
        elif add == 0x08:
            if (lastpart2 ^ 0x04) != 0:
                addend = 0
        elif add == 0x10:
            addend = buf[pos] | (buf[pos + 1] << 8)
            pos += 2
        else:
            msg("[ERRO] invalid addendum size")
            return -1

        lastpart2 = part2

        rel = dict(symbol=ofsbase | (addrbase << 8), offset=offset, base=0,
                   type=R_MIPS_NONE)
        if part2 == 0:
            continue
        elif part2 == 2:
            rel["type"] = R_MIPS_32
        elif part2 == 3:
            rel["type"] = R_MIPS_26
        elif part2 == 6:
            rel["type"] = R_MIPS_X_J26
        elif part2 == 7:
            rel["type"] = R_MIPS_X_JAL26
        elif part2 == 4:
            rel["type"] = R_MIPS_X_HI16
            rel["base"] = s16(addend)
        elif part2 in (1, 5):
            rel["type"] = R_MIPS_LO16
        else:
            msg("[ERRO] invalid relocation type")
            return -1
        relocs.append(rel)
        added += 1
    return added


def fix_relocs(prx, base):
    relocs = prx.relocs
    nrel = len(relocs)
    nph = len(prx.phdr)
    i = 0
    while i < nrel:
        rel = relocs[i]
        iofs = rel["symbol"] & 0xFF
        ival = (rel["symbol"] >> 8) & 0xFF
        if iofs >= nph or ival >= nph:
            i += 1
            continue
        ofsph = prx.phdr[iofs]["p_vaddr"]
        real_ofs = u32(base + rel["offset"] + ofsph)
        curr_base = u32(base + prx.phdr[ival]["p_vaddr"])
        rtype = rel["type"]

        if rtype == R_MIPS_HI16:
            # HI16 is fixed up as a run of HI16s followed by its matching LO16s
            inst = get_dword(real_ofs)
            addr = u32(((inst & 0xFFFF) << 16) + curr_base)
            first = i
            i += 1
            while i < nrel and relocs[i]["type"] == R_MIPS_HI16:
                i += 1
            loinst = get_dword(u32(relocs[i]["offset"] + ofsph + base)) \
                if i < nrel else 0
            addr = u32(s32(addr) + s16(loinst))
            lowaddr = addr & 0xFFFF
            hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF
            while first < i:
                ea = u32(relocs[first]["offset"] + ofsph + base)
                put_dword(ea, (get_dword(ea) & ~0xFFFF) | hiaddr)
                first += 1
            while i < nrel:
                ea = u32(relocs[i]["offset"] + ofsph + base)
                inst = get_dword(ea)
                if (inst & 0xFFFF) != (loinst & 0xFFFF):
                    break
                put_dword(ea, (inst & ~0xFFFF) | lowaddr)
                i += 1
                # the original read one entry past the end of its array here
                if i >= nrel or relocs[i]["type"] != R_MIPS_LO16:
                    break
            continue

        if rtype in (R_MIPS_16, R_MIPS_LO16):
            loinst = get_dword(real_ofs)
            addr = u32(s16(loinst) + curr_base)
            put_dword(real_ofs, (loinst & ~0xFFFF) | (addr & 0xFFFF))

        elif rtype == R_MIPS_X_HI16:
            hiinst = get_dword(real_ofs)
            addr = u32(((hiinst & 0xFFFF) << 16) + rel["base"] + curr_base)
            hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF
            put_dword(real_ofs, (hiinst & ~0xFFFF) | hiaddr)

        elif rtype in (R_MIPS_26, R_MIPS_X_J26, R_MIPS_X_JAL26):
            inst = get_dword(real_ofs)
            addr = u32(((inst & 0x03FFFFFF) << 2) + curr_base)
            put_dword(real_ofs,
                      (inst & ~0x03FFFFFF) | ((addr >> 2) & 0x03FFFFFF))

        elif rtype == R_MIPS_32:
            put_dword(real_ofs, get_dword(real_ofs) + curr_base)

        i += 1


def do_relocs(prx, base):
    prx.relocs = load_relocs(prx)
    if prx.relocs:
        fix_relocs(prx, base)


# ---------------------------------------------------------------------------
# NID tables
# ---------------------------------------------------------------------------

def find_nid_name(prx, libname, nid):
    lib = prx.nids.get(libname)
    if lib is None:
        return None
    return lib.get(nid)


def parse_psplibdoc(path):
    """psplibdoc.xml -> {libname: {nid: name}}.

    The original scanned the file with strstr(); this does a real XML parse and
    falls back to the same flat scan for the hand-edited / truncated psplibdoc
    variants that are floating around."""
    libs = {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        for lib in tree.iter("LIBRARY"):
            name_el = lib.find("NAME")
            if name_el is None or not name_el.text:
                continue
            entries = libs.setdefault(name_el.text.strip(), {})
            for group in ("FUNCTION", "VARIABLE"):
                for fn in lib.iter(group):
                    nid_el, nm_el = fn.find("NID"), fn.find("NAME")
                    if nid_el is None or nm_el is None:
                        continue
                    if not nid_el.text or not nm_el.text:
                        continue
                    try:
                        entries[int(nid_el.text.strip(), 16)] = nm_el.text.strip()
                    except ValueError:
                        pass
        if libs:
            return libs
    except Exception as exc:
        msg("XML parse failed (%s), falling back to flat scan", exc)

    try:
        with open(path, "rb") as fp:
            data = fp.read().decode("latin-1")
    except IOError:
        return {}
    for chunk in data.split("<LIBRARY>")[1:]:
        m = re.search(r"<NAME>(.*?)</NAME>", chunk, re.S)
        if not m:
            continue
        entries = libs.setdefault(m.group(1).strip(), {})
        for nid, nm in re.findall(r"<NID>(.*?)</NID>\s*<NAME>(.*?)</NAME>",
                                  chunk, re.S):
            try:
                entries[int(nid.strip(), 16)] = nm.strip()
            except ValueError:
                pass
    return libs


def find_psplibdoc():
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(ida_diskio.idadir("loaders"), "psplibdoc.xml"),
             os.path.join(here, "psplibdoc.xml"),
             os.path.join(ida_diskio.idadir("cfg"), "psplibdoc.xml")]
    inp = ida_nalt.get_input_file_path()
    if inp:
        cands.append(os.path.join(os.path.dirname(inp), "psplibdoc.xml"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return ida_kernwin.ask_file(False, "*.xml",
                                "Select psplibdoc.xml (optional, Cancel to skip)")


def load_nid_tbl(prx):
    prx.nids = {}
    path = find_psplibdoc()
    if path:
        prx.nids = parse_psplibdoc(path)
        msg("psplibdoc: %d libraries from %s", len(prx.nids), path)
    else:
        msg("no psplibdoc.xml, using the built-in tables only")

    # built-ins from scelibnids.c; they only fill gaps psplibdoc left
    for libname, table in (("syslib", G_SYSLIB),
                           ("sceLibc", G_SCELIBC),
                           ("sceLibm", G_SCELIBM)):
        entries = prx.nids.setdefault(libname, {})
        for nid, nm in table.items():
            entries.setdefault(nid, nm)


# ---------------------------------------------------------------------------
# module info / exports / imports
# ---------------------------------------------------------------------------

def load_module_info(prx, base):
    idx = find_section(prx, PSP_MODULE_INFO_NAME)
    file_off = None
    mi_ea = ida_idaapi.BADADDR

    if idx > 0:
        file_off = prx.shdr[idx]["sh_offset"]
        mi_ea = prx.shdr[idx]["sh_addr"] + base
    elif prx.phdr:
        # no section table: ph[0].p_paddr points at .rodata.sceModuleInfo
        paddr = prx.phdr[0]["p_paddr"] & 0x0FFFFFFF
        file_off = paddr
        mi_ea = prx.phdr[0]["p_vaddr"] + base + (paddr - prx.phdr[0]["p_offset"])

    if file_off is None or file_off + MODINFO.size > prx.size:
        msg("[ERRO] no module info found")
        return

    flags, name, gp, exports, exp_end, imports, imp_end = \
        MODINFO.unpack_from(prx.buf, file_off)
    name = name.split(b"\x00")[0].decode("latin-1")
    prx.modinfo = dict(flags=flags, name=name, gp=gp, exports=exports,
                       exp_end=exp_end, imports=imports, imp_end=imp_end)
    prx.modinfo_ea = mi_ea

    msg("Prx Module Info:")
    msg("  Name    : %s", name)
    msg("  Flags   : 0x%08X", flags)
    msg("  GP      : 0x%08X", gp)
    msg("  Exports : 0x%08X .. 0x%08X", exports + base, exp_end + base)
    msg("  Imports : 0x%08X .. 0x%08X", imports + base, imp_end + base)

    ida_lines.add_extra_cmt(base, True,
                            "PRX module '%s'  flags %08X  gp %08X"
                            % (name, flags, gp))

    make_string(mi_ea + MI_NAME, PSP_MODULE_MAX_NAME)
    name_ea(mi_ea + MI_NAME, "_module_name")
    for off, nm in ((MI_FLAGS, "_module_flags"),
                    (MI_GP, "_module_gp"),
                    (MI_EXPORTS, "_module_exports"),
                    (MI_EXP_END, "_module_exp_end"),
                    (MI_IMPORTS, "_module_imports"),
                    (MI_IMP_END, "_module_imp_end")):
        make_dword(mi_ea + off)
        name_ea(mi_ea + off, nm)
    if exp_end:
        make_dword(exp_end + base)
        name_ea(exp_end + base, "_exp_end")
    if imp_end:
        make_dword(imp_end + base)
        name_ea(imp_end + base, "_imp_end")


def load_single_export(prx, stub, idx):
    name_ptr, flags, counts, exports = stub
    if name_ptr == 0:
        # the unnamed first export is the system one
        libname = PSP_SYSTEM_EXPORT
    else:
        libname = read_cstr(name_ptr)
        make_string(name_ptr)
        name_ea(name_ptr, "export_%d_name" % idx)

    v_count = (counts >> 8) & 0xFF
    f_count = (counts >> 16) & 0xFFFF
    entsize = counts & 0xFF
    total = v_count + f_count
    exp_addr = exports

    for _ in range(f_count):
        nid = get_dword(exp_addr)
        nm = find_nid_name(prx, libname, nid) or ("%s_%08x" % (libname, nid))
        target = get_dword(exp_addr + 4 * total)
        name_ea(target, nm)
        make_dword(exp_addr + 4 * total)
        make_dword(exp_addr)
        name_ea(exp_addr, "export_%d_%s_nid" % (idx, nm))
        exp_addr += 4

    for _ in range(v_count):
        nid = get_dword(exp_addr)
        nm = find_nid_name(prx, libname, nid) or ("%s_%08x" % (libname, nid))
        make_dword(exp_addr + 4 * total)
        make_dword(exp_addr)
        name_ea(exp_addr, "export_%d_%s_nid" % (idx, nm))
        exp_addr += 4

    msg("export lib '%s': %d funcs, %d vars", libname, f_count, v_count)
    return entsize


def load_exports(prx, base):
    if not prx.modinfo:
        return
    exp_base = prx.modinfo["exports"]
    exp_end = prx.modinfo["exp_end"]
    if not exp_base:
        return
    idx = 0
    while exp_end - exp_base >= 16:
        ea = exp_base + base
        raw = ida_bytes.get_bytes(ea, 16)
        if raw is None or len(raw) < 16:
            break
        stub = struct.unpack("<4I", raw)
        for off, suffix in ((EXP_COUNTS, "_counts"), (EXP_EXPORTS, "_exports"),
                            (EXP_FLAGS, "_flags"), (EXP_NAME, "")):
            make_dword(ea + off)
            name_ea(ea + off, "export_%d%s" % (idx, suffix))
        entsize = load_single_export(prx, stub, idx)
        if entsize <= 0:
            break
        exp_base += entsize * 4
        idx += 1


def load_single_import(prx, stub, idx):
    name_ptr, flags, counts, nids, funcs, variables = stub
    if name_ptr == 0:
        msg("[ERRO] Import libraries must have a name")
        return 0
    libname = read_cstr(name_ptr)
    make_string(name_ptr)
    name_ea(name_ptr, "import_%d_name" % idx)

    v_count = (counts >> 8) & 0xFF
    f_count = (counts >> 16) & 0xFFFF
    entsize = counts & 0xFF

    nid_addr, func_addr, var_addr = nids, funcs, variables
    for _ in range(f_count):
        nid = get_dword(nid_addr)
        nm = find_nid_name(prx, libname, nid) or ("%s_%08x" % (libname, nid))
        name_ea(func_addr, nm)
        make_dword(nid_addr)
        name_ea(nid_addr, "import_%d_%s_nid" % (idx, nm))
        nid_addr += 4
        func_addr += 8

    for _ in range(v_count):
        var_ea = get_dword(var_addr)
        nid = get_dword(var_addr + 4)
        nm = find_nid_name(prx, libname, nid) or ("%s_%08x" % (libname, nid))
        name_ea(var_ea, nm)
        make_dword(var_addr + 4)
        name_ea(var_addr + 4, "import_%d_%s_nid" % (idx, nm))
        var_addr += 8

    msg("import lib '%s': %d funcs, %d vars", libname, f_count, v_count)
    return entsize


def load_imports(prx, base):
    if not prx.modinfo:
        return
    imp_base = prx.modinfo["imports"]
    imp_end = prx.modinfo["imp_end"]
    if not imp_base:
        return
    idx = 0
    while imp_end - imp_base >= PSP_IMPORT_BASE_SIZE:
        ea = imp_base + base
        raw = ida_bytes.get_bytes(ea, 24)
        if raw is None or len(raw) < 24:
            break
        stub = struct.unpack("<6I", raw)
        for off, suffix in ((IMP_COUNTS, "_counts"), (IMP_FLAGS, "_flags"),
                            (IMP_NAME, ""), (IMP_NIDS, "_nids"),
                            (IMP_FUNCS, "_funcs")):
            make_dword(ea + off)
            name_ea(ea + off, "import_%d%s" % (idx, suffix))
        entsize = load_single_import(prx, stub, idx)
        if entsize <= 0:
            break
        imp_base += entsize * 4
        idx += 1


def find_gp_sreg():
    """The MIPS module exposes $gp twice: as GPR 28 (what str2reg() returns)
    and as a virtual segment register at the end of the sreg range.  Only the
    latter can carry a per-segment default value."""
    names = ida_idp.ph_get_regnames()
    first = ida_idp.ph_get_reg_first_sreg()
    last = ida_idp.ph_get_reg_last_sreg()
    for rg in range(first, last + 1):
        if rg < len(names) and names[rg] == "gp":
            return rg
    return -1


def set_gp(prx):
    if not prx.modinfo or prx.modinfo_ea == ida_idaapi.BADADDR:
        return
    gp_reg = find_gp_sreg()
    if gp_reg < 0:
        return
    # take the *relocated* value out of the database: gp is usually relocated
    # against the data segment, not the text one, so modinfo["gp"] + base is
    # not the same thing
    gp_val = get_dword(prx.modinfo_ea + MI_GP)
    if gp_val in (0, 0xFFFFFFFF):
        return
    ea = ida_segment.get_first_segment_ea()
    while ea != ida_idaapi.BADADDR:
        ida_segregs.set_default_sreg_value_ea(ea, gp_reg, gp_val)
        ida_segregs.split_sreg_range(ea, gp_reg, gp_val,
                                     ida_segregs.SR_user, True)
        ea = ida_segment.get_next_segment_ea(ea)
    msg("$gp = 0x%08X", gp_val)


# ---------------------------------------------------------------------------
# loader entry points
# ---------------------------------------------------------------------------

def accept_file(li, filename):
    if not is_prx(li):
        return 0
    return {"format": "PSP PRX Loader", "processor": "psp"}


def load_file(li, neflags, fmt):
    # IDA 9.4's MIPS module carries the Allegrex variant as "psp"
    if ida_idp.ph_get_id() != ida_idp.PLFM_MIPS:
        if not ida_idp.set_processor_type("psp",
                                          ida_idp.SETPROC_LOADER_NON_FATAL):
            ida_idp.set_processor_type("mipsl", ida_idp.SETPROC_LOADER)

    li.seek(0, os.SEEK_END)
    size = li.tell()
    li.seek(0)
    buf = li.read(size)

    prx = PrxInfo(buf)
    prx.ehdr = parse_ehdr(buf)

    load_nid_tbl(prx)

    if prx.ehdr["e_entry"] < 0x08800000:
        base = ida_kernwin.ask_addr(EBOOT_BASE_ADDR,
                                    "Set base address for relocation:")
        if base is None:
            base = EBOOT_BASE_ADDR
    else:
        base = 0
    msg("base address: 0x%08X", base)

    load_section_headers(prx)
    if load_program_headers(prx) < 0:
        ida_loader.loader_failure("bad program headers")

    if prx.ehdr["e_shnum"] > 0:
        load_sections(li, prx, base)
    else:
        load_programs(li, prx, base)

    create_bss(prx, base)
    do_relocs(prx, base)

    load_module_info(prx, base)
    load_exports(prx, base)
    load_imports(prx, base)

    # $gp is what makes MIPS data references readable; the C loader never set it
    set_gp(prx)

    entry = u32(prx.ehdr["e_entry"] + base)
    if ida_segment.getseg(entry) is not None:
        ida_entry.add_entry(0, entry, "module_start", True)

    ida_nalt.set_imagebase(base)
    return 1


# ---------------------------------------------------------------------------
# built-in NID tables (generated from scelibnids.c)
# ---------------------------------------------------------------------------

G_SYSLIB = {
    0xD3744BE0: "module_bootstart",
    0xF01D73A7: "module_info",
    0x2F064FA6: "module_reboot_before",
    0xADF12745: "module_reboot_phase",
    0xD632ACDB: "module_start",
    0x0F7C276C: "module_start_thread_parameter",
    0xCEE8593C: "module_stop",
    0xCF0CC697: "module_stop_thread_parameter",
    0xF4F4299D: "module_reboot_before_thread_parameter",
    0x11B97506: "module_sdk_version",
    0x900DADE1: "module_linked",
    0x592743D8: "module_unlinked",
}


G_SCELIBC = {
    0x001F6FF9: "_malloc_usable_size_r",
    0x0044FF4B: "__getdelim",
    0x00732C47: "iswgraph",
    0x00BFC9DC: "ldiv",
    0x014E4A73: "mallinfo",
    0x017739BA: "strptime",
    0x02FDCBC6: "l64a",
    0x035CF8B3: "malloc_stats",
    0x03894E98: "_perror_r",
    0x04103ACB: "argz_extract",
    0x059A0407: "_mblen_r",
    0x0629E7E1: "_lshift",
    0x090E02B5: "drand48",
    0x097049BD: "bcopy",
    0x09E7F7E1: "wcscmp",
    0x0A7EC130: "wcswidth",
    0x0B9558BF: "fcvtbuf",
    0x0C8638DA: "close",
    0x0CF9A48C: "__errno",
    0x0D188658: "strstr",
    0x0D1CDEDE: "localeconv",
    0x0D1EE173: "_putchar_r",
    0x0DFB7B6C: "strpbrk",
    0x0ED149A8: "valloc",
    0x10B6B9C4: "envz_get",
    0x10F3BB61: "memset",
    0x11256476: "putc_unlocked",
    0x113CCCA4: "_l64a_r",
    0x11595AA8: "_atol_r",
    0x118003EE: "_fseek_r",
    0x11AA4488: "__exp10",
    0x123993BA: "_sbrk_r",
    0x132F9F0B: "_dcvt",
    0x1493EBD9: "wmemset",
    0x156E4652: "__env_lock",
    0x17BF7B66: "fgetc",
    0x17C23ADE: "exit",
    0x1830070B: "__dprintf",
    0x18AD3F7E: "_sprintf_r",
    0x1A059DBF: "_asprintf_r",
    0x1AB53A58: "strtok_r",
    0x1B00FB95: "qsort",
    0x1B3AC62A: "wmemchr",
    0x1B571B01: "_towctrans_r",
    0x1B62B87B: "envz_merge",
    0x1BADE054: "fiprintf",
    0x1CD0352B: "cfree",
    0x1E02C5A7: "_fopen_r",
    0x1E6C6D30: "argz_count",
    0x1F1F0226: "div",
    0x1F29A719: "malloc_trim",
    0x1F94A881: "__getline",
    0x206633D6: "isascii",
    0x2205CFB7: "iswspace",
    0x220B7B1A: "fileno",
    0x225E66F2: "lrand48",
    0x226CAFEF: "fseek",
    0x230201FB: "mblen",
    0x2307BDBA: "_puts_r",
    0x2345C4B2: "_findenv",
    0x2361BE8D: "wcsncpy",
    0x23A9C4C9: "strtof",
    0x23BDE4BE: "_wctomb_r",
    0x243665ED: "rindex",
    0x2561E442: "__assert",
    0x26471E98: "envz_add",
    0x269CE00B: "_tempnam_r",
    0x26D7E209: "_ftell_r",
    0x274BB5A2: "ftello",
    0x27739A84: "_strtold",
    0x27F9052C: "sscanf",
    0x2A5001DF: "__malloc_unlock",
    0x2B9F5448: "cleanup_glue",
    0x2BDBE99E: "gmtime_r",
    0x2D28C86A: "_wcstombs_r",
    0x2DA50A4F: "link",
    0x2DA7DFD2: "iswalnum",
    0x2E80A2F3: "fread",
    0x2FD01E39: "wcslcpy",
    0x302A6DE7: "strerror",
    0x305C3A5E: "_freopen_r",
    0x31707674: "scanf",
    0x318EAA15: "_erand48_r",
    0x31B2E51A: "hcreate",
    0x320FA6EB: "_fwalk",
    0x321C257A: "_strtol_r",
    0x34F4DCAB: "iswlower",
    0x363C838F: "_wctrans_r",
    0x3670AE63: "ecvtbuf",
    0x381031DB: "wcsncmp",
    0x382D4A60: "ecvt",
    0x38497413: "iswctype",
    0x38D5E989: "_fseeko_r",
    0x3901ED92: "putchar_unlocked",
    0x3A5AFC93: "gmtime",
    0x3B2BDCF2: "_init_signal",
    0x3B8D1A61: "tfind",
    0x3C25F7AC: "_dtoa_r",
    0x3D32ABBA: "_rewind_r",
    0x3E580704: "argz_add_sep",
    0x3EB35691: "strcasecmp",
    0x3EC5BBF6: "tolower",
    0x3F08CADD: "__signgam",
    0x3F381760: "atof",
    0x3F939123: "getc_unlocked",
    0x40E1503B: "fsetpos",
    0x40E622F4: "feof",
    0x40F054E1: "atoll",
    0x411B4582: "abs",
    0x41B37D98: "sbrk",
    0x428E8A62: "strupr",
    0x42B051FD: "fopen",
    0x42D41903: "_mbstowcs_r",
    0x42E77521: "__reclaim_buf",
    0x42F5B189: "iswcntrl",
    0x43F3B3EE: "sceLibcThreadOnExit",
    0x44E5C924: "_mstats_r",
    0x44F603BE: "atoff",
    0x453F2836: "gettimeofday",
    0x45425298: "a64l",
    0x476FD94A: "strcat",
    0x47863CD4: "_read_r",
    0x47DD934D: "strtol",
    0x4805D082: "isblank",
    0x481C9ADA: "malloc",
    0x49C00359: "_Exit",
    0x4C0AB7F9: "hdestroy",
    0x4C0B9F8F: "seed48",
    0x4C0E0274: "strrchr",
    0x4CA3F245: "vprintf",
    0x4D46EEA7: "_vfprintf_r",
    0x4DB0254B: "_atoll_r",
    0x4EE7CA15: "_strtod_r",
    0x4F66EEEB: "towctrans",
    0x4FA64D28: "_putchar_unlocked_r",
    0x5015A892: "vfiprintf",
    0x50AF5E1B: "on_exit",
    0x518C81F1: "_tzset_r",
    0x51BBB764: "vasprintf",
    0x520990F1: "ctime",
    0x525F7602: "tdelete",
    0x52DF196C: "strlen",
    0x538A61D8: "setbuf",
    0x53B31B57: "wctomb",
    0x542EAF5E: "putenv",
    0x54A961CD: "_valloc_r",
    0x54F3C563: "vsprintf",
    0x55A30A8D: "isxdigit",
    0x57272360: "fstat",
    0x588499DB: "remove",
    0x59AFE62B: "mkstemp",
    0x59E7DC9E: "wmemcpy",
    0x5A3D5A2F: "_printf_r",
    0x5B0648E7: "_flush_cache",
    0x5C13F31E: "_gets_r",
    0x5D5C997F: "twalk",
    0x5EB65777: "getenv",
    0x60054052: "rand",
    0x608DD293: "_cleanup_r",
    0x614357CC: "fprintf",
    0x61D8A535: "_nrand48_r",
    0x62AE052F: "strspn",
    0x64785D58: "_close_r",
    0x6535AC9C: "hcreate_r",
    0x65E691CB: "_system_r",
    0x65FC2A16: "swab",
    0x689941F5: "_mbrtowc_r",
    0x68A78817: "memchr",
    0x690DF795: "envz_entry",
    0x69928474: "_snprintf_r",
    0x69A04346: "_strtoull_r",
    0x69F7DF0D: "_realloc_r",
    0x6A5ACA36: "_malloc_trim_r",
    0x6A7900E1: "strtoul",
    0x6ACDA991: "_getpid_r",
    0x6B65A65A: "fgets",
    0x6D48778B: "ungetc",
    0x6DB9FECF: "_tmpfile_r",
    0x6DD39CE2: "fscanf",
    0x6DF635CD: "setbuffer",
    0x6F2306D1: "iscntrl",
    0x6F6DA204: "rename",
    0x704953FF: "mbrtowc",
    0x710F03AF: "erand48",
    0x717FC004: "_vsscanf_r",
    0x718574CB: "_wcrtomb_r",
    0x72B43391: "getc",
    0x73A7ED28: "mstats",
    0x7440FE05: "__sigtramp",
    0x74F85D04: "wcstombs",
    0x75A1CAFA: "_memalign_r",
    0x75B18731: "toascii",
    0x75CF2A10: "tmpnam",
    0x761E7F31: "system",
    0x7661E728: "sprintf",
    0x79064851: "srand",
    0x790CB79F: "_fdopen_r",
    0x79E6DC88: "_getchar_r",
    0x79EC56DB: "hsearch_r",
    0x79F8A3A5: "_vsprintf_r",
    0x7AB35214: "strncmp",
    0x7AC8DB34: "wctrans",
    0x7B583F6E: "strlcat",
    0x7B6D9378: "lcong48",
    0x7BA27B01: "strncasecmp",
    0x7BB52208: "_tmpnam_r",
    0x7C43086E: "localtime_r",
    0x7D1A9B56: "fwrite",
    0x7D672E05: "vfscanf",
    0x7E338487: "getchar",
    0x7E391025: "getsubopt",
    0x7E8C6C51: "__env_unlock",
    0x7EF3FBEC: "realloc",
    0x7F04ABBE: "putw",
    0x7F7851C2: "mbtowc",
    0x7F8A6F23: "bcmp",
    0x7FF59A02: "__getreent",
    0x81287F43: "wcsrchr",
    0x81A25FD2: "asctime",
    0x81D0D1F7: "memcmp",
    0x81D1DE66: "strlwr",
    0x82510268: "wcsrtombs",
    0x828631DF: "_vasprintf_r",
    0x82C9EC33: "wcwidth",
    0x84F44D55: "iswalpha",
    0x851DABD0: "argz_replace",
    0x86052A87: "getopt",
    0x8659483A: "wcscpy",
    0x866D7721: "setlinebuf",
    0x86DB5E77: "strndup",
    0x86FEFCE9: "bzero",
    0x87041BC8: "__malloc_lock",
    0x87B59671: "times",
    0x87F8D2DA: "strtok",
    0x884121E0: "fcloseall",
    0x8872237F: "__cxa_finalize",
    0x891B5996: "_lseek_r",
    0x8934A0FC: "mallopt",
    0x89985678: "tmpfile",
    0x89B79CB1: "strcspn",
    0x8A74425E: "strtoull",
    0x8AD63308: "argz_append",
    0x8BAA96F3: "_vprintf_r",
    0x8BE3C75F: "open",
    0x8C0AAADF: "_vsnprintf_r",
    0x8C7E4603: "_mktm_r",
    0x8C9BACB8: "fcvt",
    0x8CCCA6AC: "_setlocale_r",
    0x8D078576: "_putenv_r",
    0x8EF7ED93: "argz_add",
    0x8FA69343: "argz_create",
    0x90970FF3: "getchar_unlocked",
    0x909C228B: "setjmp",
    0x90C5573D: "strnlen",
    0x93160ABD: "fgetpos",
    0x95CF0BA8: "isalpha",
    0x95F2D243: "iswupper",
    0x970AE97C: "_mkstemp_r",
    0x971DB6F6: "_link_r",
    0x975E323B: "wctob",
    0x97AA4C55: "gcvtf",
    0x986413F0: "wmemcmp",
    0x993AE899: "_raise_r",
    0x9A4BF9AA: "wcsnlen",
    0x9C56D255: "_mrand48_r",
    0x9CFC2650: "_fscanf_r",
    0x9E12F540: "_strtoul_r",
    0x9EB30A18: "_unsetenv_r",
    0x9FE90D6A: "freopen",
    0xA008CF03: "_free_r",
    0xA04C19E8: "llabs",
    0xA0B04378: "getw",
    0xA1455F97: "_mktemp_r",
    0xA1BCC34A: "_findenv_r",
    0xA2770704: "strerror_r",
    0xA3DED6A7: "srand48",
    0xA48D2592: "memmove",
    0xA4E88DAA: "_sscanf_r",
    0xA56248CB: "mbrlen",
    0xA5CA19E3: "_open_r",
    0xA681880B: "argz_create_sep",
    0xA6B16465: "_ldtoa_r",
    0xA6B67503: "ferror",
    0xA7419681: "pvalloc",
    0xA7C286AB: "setenv",
    0xA8040B4E: "mbsrtowcs",
    0xA8EBA230: "strsep",
    0xA97E27CB: "wcscoll",
    0xA9BBF903: "setlocale",
    0xAA0D3B0F: "_cleanup",
    0xAA4AAB36: "signal",
    0xAA65B287: "_init_signal_r",
    0xAAD41BF4: "_stat_r",
    0xAB7592FF: "memcpy",
    0xABAEA15F: "envz_strip",
    0xAC028BA6: "mbsinit",
    0xAC333B61: "_mallopt_r",
    0xAC4431D8: "_strdup_r",
    0xAD8AF84F: "free",
    0xAD8C0509: "_write_r",
    0xADA10FF3: "islower",
    0xAE0F2785: "_tolower",
    0xAE15704E: "mktemp",
    0xAE3A09DE: "strftime",
    0xAE4A2837: "tdestroy",
    0xAEDF26D9: "vfprintf",
    0xAF21DEF4: "towupper",
    0xAF975018: "fseeko",
    0xAFF06624: "mempcpy",
    0xB123B9BC: "iprintf",
    0xB1A37F44: "fflush",
    0xB1DC2AE8: "strchr",
    0xB2191778: "fclose",
    0xB228C4CD: "_fcloseall_r",
    0xB24E6623: "unsetenv",
    0xB2A8A96F: "isgraph",
    0xB2EB3F2E: "gcvt",
    0xB3092C0B: "argz_stringify",
    0xB365ECEB: "wcsncat",
    0xB4019F3B: "difftime",
    0xB47E4C0D: "_fgetpos_r",
    0xB4962005: "wctype",
    0xB49A7697: "strncpy",
    0xB64D85F8: "mbstowcs",
    0xB6DDAFA7: "read",
    0xB71B578A: "lldiv",
    0xB73CFB70: "_times_r",
    0xB7D51248: "strcoll",
    0xB856048A: "_fsetpos_r",
    0xB8A55300: "atoi",
    0xB8C56C3E: "_fstat_r",
    0xB8D7C11E: "memalign",
    0xBA4268E8: "strdup",
    0xBA64636D: "calloc",
    0xBB9F5B8E: "__sigtramp_r",
    0xBBC45102: "_setmodreent",
    0xBBD2DA12: "atol",
    0xBDBAAFAA: "_signal_r",
    0xBEBDC49A: "strtoll",
    0xBED8D52D: "vsscanf",
    0xBFF7E760: "gets",
    0xC07C8CA1: "_lcong48_r",
    0xC0AB8932: "strcmp",
    0xC0E9DF4A: "_scanf_r",
    0xC11B6140: "_getmodreent",
    0xC1251FFE: "_kill_r",
    0xC15B0FC8: "kill",
    0xC1C6D0E1: "write",
    0xC2145E80: "snprintf",
    0xC27E4D42: "_seed48_r",
    0xC297BCB9: "wcspbrk",
    0xC36D8D42: "_atoi_r",
    0xC374F25E: "iswprint",
    0xC3A20A1C: "ecvtf",
    0xC3AE5755: "towlower",
    0xC4C4262B: "getpid",
    0xC53B9FE6: "iswblank",
    0xC57740C8: "fputs",
    0xC5807E8F: "asprintf",
    0xC6C3ABA1: "_drand48_r",
    0xC73AB8DC: "isspace",
    0xC75A16FC: "stat",
    0xC7C2B1A9: "_reent_init_ptr",
    0xC7D81FBA: "_localeconv_r",
    0xC839346C: "iswdigit",
    0xC86AD790: "wcsspn",
    0xC8845A78: "argz_next",
    0xC9546B19: "_iprintf_r",
    0xC98E5E81: "_malloc_stats_r",
    0xCA3DCDB5: "_vfscanf_r",
    0xCA596941: "tsearch",
    0xCAB439DF: "printf",
    0xCB9069AA: "_getchar_unlocked_r",
    0xCBCBD9F0: "strlcpy",
    0xCC045BCD: "ftell",
    0xCC11CD1E: "wmemmove",
    0xCE2261F4: "wcscspn",
    0xCE2A49A5: "strxfrm",
    0xCE2F7487: "toupper",
    0xCEF4E667: "setvbuf",
    0xCF69C7DE: "wcschr",
    0xCF6BB40B: "_toupper",
    0xCFA7DAF6: "siprintf",
    0xD03B9E65: "wcsstr",
    0xD041BD54: "_mbtowc_r",
    0xD0488FDB: "_jrand48_r",
    0xD07B00A9: "malloc_usable_size",
    0xD0A99688: "envz_remove",
    0xD0F34BBA: "tzset",
    0xD16166DE: "nl_langinfo",
    0xD176078F: "ffs",
    0xD1CD40E5: "index",
    0xD20386F9: "isalnum",
    0xD30CFAD5: "_getenv_r",
    0xD3D1A3B9: "strncat",
    0xD4126493: "fputc",
    0xD5162E4C: "sceLibcThreadAtExit",
    0xD59246BF: "_wctype_r",
    0xD5A27B26: "_mbsrtowcs_r",
    0xD6900820: "_ftello_r",
    0xD694DC32: "_gcvt",
    0xD6960642: "wcslen",
    0xD768752A: "putchar",
    0xD778FCA9: "strtod",
    0xD7CC5BF2: "localtime",
    0xD850C0C9: "btowc",
    0xD89F56C6: "nrand48",
    0xD8D13D82: "putc",
    0xD97C8CB9: "puts",
    0xDABBE3BC: "wcscat",
    0xDB9ACA25: "__hash_open",
    0xDC52AE3C: "argz_insert",
    0xDCC5A5C8: "hdestroy_r",
    0xDE3F98E0: "rewind",
    0xDF9FABCD: "argz_delete",
    0xE048E1C6: "perror",
    0xE0B17D65: "raise",
    0xE0BB8F76: "clearerr",
    0xE14059A7: "isupper",
    0xE1E3BD28: "mrand48",
    0xE1E8E050: "sceLibcThreadExit",
    0xE230590D: "lseek",
    0xE345091C: "ctime_r",
    0xE35A8AD2: "rand_r",
    0xE393986E: "_strndup_r",
    0xE39C3DB4: "wcrtomb",
    0xE3E829A8: "wcslcat",
    0xE4298F38: "memccpy",
    0xE42FEA2F: "iswpunct",
    0xE43392F0: "mktime",
    0xE466A65C: "vscanf",
    0xE4DA3BCA: "__eprintf",
    0xE56008E6: "_setenv_r",
    0xE6A1687A: "_lrand48_r",
    0xE793AFCD: "_gettimeofday_r",
    0xE821E845: "bsearch",
    0xE8436AB4: "ispunct",
    0xE877AA3E: "isprint",
    0xE98C2922: "_remove_r",
    0xEB6644C2: "vsnprintf",
    0xEC50F8A4: "isdigit",
    0xEC6F1CF2: "strcpy",
    0xECC54493: "_rename_r",
    0xEE9C0825: "_mallinfo_r",
    0xEFA66EAC: "jrand48",
    0xF006704E: "_wcsrtombs_r",
    0xF04616B6: "abort",
    0xF09C6A0A: "iswxdigit",
    0xF0DE4B55: "_vscanf_r",
    0xF1013F85: "_malloc_r",
    0xF1BB247F: "fdopen",
    0xF4D45E7A: "_srand48_r",
    0xF4EC6308: "asctime_r",
    0xF75FB37E: "_pvalloc_r",
    0xF7D3BD63: "tempnam",
    0xF7E9A736: "_clrmodreent",
    0xFC0A7550: "_strtoll_r",
    0xFC4E802A: "fcvtf",
    0xFD5C0509: "_calloc_r",
    0xFDB25338: "atexit",
    0xFDF90C93: "_vfiprintf_r",
    0xFE44BD6B: "labs",
    0xFEBB6952: "_user_strerror",
    0xFFFB7747: "hsearch",
    0x01AC1136: "environ",
    0x12D93A1E: "__lc_ctype",
    0x14B9DE7A: "_tzname",
    0x2F12DAE8: "_timezone",
    0x3D7AD040: "_ctype_",
    0x695216D9: "opterr",
    0x8E839176: "optind",
    0x987F68B5: "__mb_cur_max",
    0xAC18C295: "_daylight",
    0xB24040B8: "__ctype_ptr",
    0xC29ABC86: "__unctrllen",
    0xDF10CC56: "__unctrl",
    0xE06872BD: "_impure_ptr",
}


G_SCELIBM = {
    0x023B0BF5: "__ieee754_sqrt",
    0x0354ECAF: "asinhf",
    0x03CFE249: "ilogb",
    0x0405D738: "scalblnf",
    0x05BC86D4: "__ieee754_yn",
    0x06BC566C: "log1pf",
    0x09F5941E: "sqrtf",
    0x0AC73AB1: "infinityf",
    0x0C3AD395: "erf",
    0x0C5C9119: "logb",
    0x0CF83A61: "ceil",
    0x0E2F937F: "expf",
    0x0EF32BC1: "__ieee754_j1f",
    0x11819BA0: "lroundf",
    0x119FAF5C: "powf",
    0x126B4C0C: "infinity",
    0x12F83FBB: "asinf",
    0x133ED63B: "__ieee754_scalbf",
    0x1563AD6D: "__ieee754_log10",
    0x19F78E5B: "rint",
    0x1A1FC867: "frexp",
    0x1BF43715: "lrintf",
    0x1C507D72: "scalbnf",
    0x1D95DAFF: "tgammaf",
    0x1EA78E45: "tanf",
    0x2187C6F2: "acoshf",
    0x245617DF: "log10f",
    0x2571C8CA: "nearbyint",
    0x269C8D1E: "trunc",
    0x26BD8DEC: "__ieee754_y0",
    0x26E59703: "__ieee754_atanh",
    0x27D2E41C: "lgamma_r",
    0x29BC98E9: "exp2f",
    0x2C27F4A2: "frexpf",
    0x2C987902: "fabsf",
    0x2CCD9731: "__ieee754_asin",
    0x2F9E0E6A: "isnan",
    0x318CECBA: "expm1",
    0x33C2AB7B: "log",
    0x35A70F7D: "sincos",
    0x37711BF5: "fma",
    0x39B0E7F2: "__ieee754_y0f",
    0x39C71322: "isnanf",
    0x3A0856D0: "isinf",
    0x3BC9735C: "drem",
    0x3C15F372: "sqrt",
    0x3E09BFED: "modf",
    0x3E9D60E9: "lgammaf",
    0x3EFC2154: "cbrt",
    0x3F00D0D6: "__fpclassifyd",
    0x3FF9705D: "copysign",
    0x404BAB3D: "scalbf",
    0x4186CEE6: "gammaf_r",
    0x42078F32: "acos",
    0x42129267: "j1",
    0x451FF45F: "matherr",
    0x466F446E: "__ieee754_rem_pio2f",
    0x473A7AEB: "rintf",
    0x484A3B9F: "roundf",
    0x4AC0147D: "sin",
    0x4AD2E899: "__ieee754_cosh",
    0x4D2CCC5B: "cos",
    0x4D5077F0: "atan",
    0x4E6A1AF1: "fdim",
    0x5268DEE6: "atanhf",
    0x586E43AE: "hypot",
    0x595AB11F: "fmin",
    0x5D4061A4: "finite",
    0x5D959DD8: "remainder",
    0x5DE795ED: "__ieee754_j0f",
    0x5EFD8C68: "sinh",
    0x619D480C: "pow",
    0x6200E685: "remquof",
    0x622D4161: "sincosf",
    0x625A9A94: "fmaxf",
    0x6320DF2D: "nextafter",
    0x63D301E8: "ynf",
    0x65127B47: "__ieee754_scalb",
    0x68AF59D1: "__ieee754_lgamma_r",
    0x68DDD3D7: "asinh",
    0x6C71E7EC: "__ieee754_sinh",
    0x6D0A59F0: "round",
    0x6D41A21F: "__signbitd",
    0x6F29B661: "fmodf",
    0x705AF3F4: "__ieee754_rem_pio2",
    0x710E5393: "__ieee754_gammaf_r",
    0x72824263: "tgamma",
    0x7306A9DE: "scalb",
    0x743928E5: "nearbyintf",
    0x74FBBD0D: "copysignf",
    0x781FF587: "j0f",
    0x7A020F4E: "ldexpf",
    0x7BBF1013: "__ieee754_gamma_r",
    0x7DAB1236: "jn",
    0x7E27F05D: "acosh",
    0x7E35A7B1: "atan2",
    0x7E66D731: "atan2f",
    0x7EDCC45E: "floorf",
    0x820C80E6: "acosf",
    0x878D1DFB: "scalbn",
    0x882AA806: "lgammaf_r",
    0x88E0C2D9: "truncf",
    0x8C69C618: "__ieee754_remainder",
    0x8DFBB22F: "jnf",
    0x8FB39319: "lgamma",
    0x9030AE22: "modff",
    0x9119195D: "coshf",
    0x95678920: "__ieee754_expf",
    0x9593EC0A: "ldexp",
    0x95C7BDB0: "__ieee754_y1",
    0x963EB4E8: "__ieee754_j1",
    0x9683C393: "__ieee754_coshf",
    0x9873DBD4: "y0",
    0x9B8A3736: "__ieee754_jnf",
    0x9BA60B14: "__ieee754_atan2",
    0x9C9D02C6: "significand",
    0x9D79E4E1: "fmod",
    0x9DB4DDFE: "cbrtf",
    0x9EC3F79A: "__ieee754_lgammaf_r",
    0x9FFB9478: "__ieee754_remainderf",
    0xA023C87A: "__ieee754_y1f",
    0xA0A9019A: "dremf",
    0xA11394AA: "sinhf",
    0xA1B6CBE0: "__ieee754_pow",
    0xA1E9B3F6: "asin",
    0xA323E611: "nan",
    0xA4BA8476: "atanh",
    0xA5F4CF15: "lround",
    0xA6918300: "log1p",
    0xA8C07DE3: "tanh",
    0xAA08B030: "cabs",
    0xAA8DE2C8: "__ieee754_asinf",
    0xAB34AC14: "__ieee754_j0",
    0xAB405DF3: "gamma_r",
    0xAC581C05: "__ieee754_hypotf",
    0xADEF2E8D: "__ieee754_hypot",
    0xAF8B8C69: "logf",
    0xB08E6F99: "__ieee754_ynf",
    0xB14DEEEC: "__ieee754_jn",
    0xB2701BB7: "fmax",
    0xB29FE5D1: "__ieee754_exp",
    0xB52DCAEF: "fmaf",
    0xB5D54223: "tanhf",
    0xB72AE732: "fdimf",
    0xB80CF119: "erfcf",
    0xB86E1E6A: "y0f",
    0xBD55FD2B: "fminf",
    0xBFF411F3: "__ieee754_acoshf",
    0xC3F470FF: "gamma",
    0xC4269616: "logbf",
    0xC731B0C3: "__ieee754_atan2f",
    0xC732C683: "cabsf",
    0xC7AFFEA2: "cosh",
    0xC7B65D19: "fabs",
    0xC9A07B19: "lrint",
    0xC9D0F7C7: "__ieee754_log",
    0xCAF65D7F: "expm1f",
    0xCC984F83: "__fpclassifyf",
    0xCD904F35: "atanf",
    0xCE03D30C: "log10",
    0xCEBB156F: "remainderf",
    0xCF9B1E09: "nanf",
    0xD0B8F65E: "y1f",
    0xD3C98436: "floor",
    0xD414E16D: "y1",
    0xD44E3F0C: "__ieee754_sqrtf",
    0xD4B7ACA5: "__ieee754_acos",
    0xD5262A7F: "finitef",
    0xD620ADEB: "hypotf",
    0xD73D4713: "__ieee754_acosh",
    0xD7D6BF20: "ceilf",
    0xDC4D764F: "__ieee754_powf",
    0xDF0B36DF: "significandf",
    0xE0188A49: "gammaf",
    0xE02BF9D6: "ilogbf",
    0xE0743D40: "__ieee754_acosf",
    0xE13B6DAE: "sinf",
    0xE27DB786: "exp",
    0xE34CCF4D: "__ieee754_log10f",
    0xE53FA01F: "isinff",
    0xE636CE60: "j0",
    0xE8323C8F: "exp2",
    0xEB6D20A5: "cosf",
    0xEC5C24C3: "remquo",
    0xED1C5C29: "j1f",
    0xF009E93C: "erff",
    0xF0F261D1: "yn",
    0xF18CCA35: "tan",
    0xF491BBD7: "nextafterf",
    0xF54EDF4B: "__signbitf",
    0xF5E2FCFE: "__ieee754_atanhf",
    0xF621DBFD: "erfc",
    0xF65A090D: "__ieee754_sinhf",
    0xF65B16C6: "scalbln",
    0xF7004F88: "__ieee754_logf",
    0xF9CEDE73: "__ieee754_fmodf",
    0xFE7C2DE9: "__ieee754_fmod",
    0xBDBD9446: "__infinity",
    0xE322351E: "__fdlib_version",
}
