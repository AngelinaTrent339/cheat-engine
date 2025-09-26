#!/usr/bin/env python3
"""
Hash all exported function names from one or more PE DLLs using the
folded FNV-like function observed in the target (dump.bin).

Usage:
  python tools/hash_exports.py user32.dll kernel32.dll ntdll.dll dwmapi.dll -o out.csv

If a DLL argument is a bare name (e.g., user32.dll), the script will try to
locate it in %SystemRoot%\System32 and %SystemRoot%\SysWOW64. You may also pass
absolute or relative file paths.

Output:
  CSV with columns: dll,name,hash_hex,hash_dec

This tool has no external dependencies and parses PE headers directly.
"""

from __future__ import annotations
import argparse
import os
import struct
import sys
from typing import List, Tuple, Optional


def hash32(name: str) -> int:
    h = 1068554765  # seed observed in sample
    for b in name.encode('ascii', errors='ignore'):
        h = ((h ^ b) * 16777643) & 0xFFFFFFFF
    return h & 0x7FFFFFFF


class PE:
    def __init__(self, path: str):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self._parse()

    def _u16(self, off: int) -> int:
        return struct.unpack_from('<H', self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from('<I', self.data, off)[0]

    def _u64(self, off: int) -> int:
        return struct.unpack_from('<Q', self.data, off)[0]

    def _parse(self) -> None:
        # DOS header
        if self._u16(0x00) != 0x5A4D:
            raise ValueError(f'{self.path}: not an MZ file')
        e_lfanew = self._u32(0x3C)
        # PE signature
        if self._u32(e_lfanew) != 0x00004550:
            raise ValueError(f'{self.path}: invalid PE signature')
        coff = e_lfanew + 4
        machine = self._u16(coff + 0)
        num_sections = self._u16(coff + 2)
        size_opt = self._u16(coff + 16)
        opt = coff + 20
        magic = self._u16(opt + 0)
        if magic == 0x10B:
            # PE32
            dd_off = opt + 96
        elif magic == 0x20B:
            # PE32+
            dd_off = opt + 112
        else:
            raise ValueError(f'{self.path}: unknown optional header magic 0x{magic:04X}')
        # DataDirectory[0] = Export Table
        export_rva = self._u32(dd_off + 0*8)
        export_size = self._u32(dd_off + 0*8 + 4)
        # Section table
        sect_off = opt + size_opt
        sections = []
        for i in range(num_sections):
            off = sect_off + i*40
            va = self._u32(off + 12)
            vsz = self._u32(off + 8)
            raw = self._u32(off + 20)
            rsz = self._u32(off + 16)
            name = self.data[off:off+8].split(b'\x00',1)[0].decode('ascii', errors='ignore')
            sections.append((va, max(vsz, rsz), raw, name))
        self.sections = sections
        self.export_rva = export_rva
        self.export_size = export_size

    def rva_to_file(self, rva: int) -> Optional[int]:
        for va, sz, raw, _name in self.sections:
            if va <= rva < va + sz and raw != 0:
                return raw + (rva - va)
        return None

    def read_cstr(self, file_off: int) -> str:
        end = self.data.find(b'\x00', file_off)
        if end == -1:
            end = file_off
            while end < len(self.data) and self.data[end] != 0:
                end += 1
        return self.data[file_off:end].decode('ascii', errors='ignore')

    def exports(self) -> List[str]:
        if self.export_rva == 0:
            return []
        exp_off = self.rva_to_file(self.export_rva)
        if exp_off is None:
            return []
        # IMAGE_EXPORT_DIRECTORY is 40 bytes
        # fields at offsets: NumberOfNames (24), AddressOfNames (32)
        number_of_names = self._u32(exp_off + 24)
        address_of_names_rva = self._u32(exp_off + 32)
        aof_off = self.rva_to_file(address_of_names_rva)
        if aof_off is None:
            return []
        names: List[str] = []
        for i in range(number_of_names):
            name_rva = self._u32(aof_off + i*4)
            name_off = self.rva_to_file(name_rva)
            if name_off is None:
                continue
            nm = self.read_cstr(name_off)
            if nm:
                names.append(nm)
        return names


def locate_dll(arg: str) -> str:
    # If path exists as-is, use it
    if os.path.isfile(arg):
        return os.path.abspath(arg)
    # Otherwise, search System32/SysWOW64
    sysroot = os.environ.get('SystemRoot', r'C:\Windows')
    candidates = [
        os.path.join(sysroot, 'System32', arg),
        os.path.join(sysroot, 'SysWOW64', arg),
        os.path.join(os.getcwd(), arg),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise FileNotFoundError(f'Cannot locate {arg}')


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description='Hash exports (FNV-like) for one or more DLLs.')
    ap.add_argument('dlls', nargs='+', help='DLL paths or bare names (e.g., user32.dll)')
    ap.add_argument('-o', '--out', default='export-hashes.csv', help='Output CSV')
    args = ap.parse_args(argv)

    rows: List[Tuple[str, str, int]] = []
    for arg in args.dlls:
        path = locate_dll(arg)
        pe = PE(path)
        dll = os.path.basename(path)
        for name in pe.exports():
            h = hash32(name)
            rows.append((dll, name, h))

    # Write CSV
    with open(args.out, 'w', encoding='utf-8', newline='') as f:
        f.write('dll,name,hash_hex,hash_dec\n')
        for dll, name, h in rows:
            f.write(f'{dll},{name},0x{h:08X},{h}\n')
    print(f'Wrote {len(rows)} rows to {args.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))

