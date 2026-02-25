#!/usr/bin/env python3
"""
extract_firmware_packages.py - Extract embedded HWNP firmware packages from
ONT_V100R002C00SPC253.exe (or the translated/unlocked variant).

The EXE contains 6 BIN resources (IDs 130-135), each a complete HWNP firmware
package. They are used in pairs by the Enable Package menu:

  Enable Pkg 1 = BIN130 + BIN131  (V3 version devices)
  Enable Pkg 2 = BIN132 + BIN133  (V5 version devices)
  Enable Pkg 3 = BIN134 + BIN135  (new devices)

Usage:
    pip install pefile
    python3 extract_firmware_packages.py <input.exe> [output_dir]

Output directory defaults to 'firmware_packages/'.
"""
import os
import struct
import sys

try:
    import pefile
except ImportError:
    print('Error: pefile is required.  pip install pefile')
    sys.exit(1)


# BIN resource IDs and their roles
BIN_INFO = {
    130: {'pkg': 1, 'role': 'equipment',
          'desc': 'Pkg1 part A: 9 equipment.tar.gz for different firmware versions + duit9rr.sh + ramcheck'},
    131: {'pkg': 1, 'role': 'module',
          'desc': 'Pkg1 part B: single equipment.tar.gz (2 MB) + run.sh (Telnet+SSH enabler)'},
    132: {'pkg': 2, 'role': 'factory_reset',
          'desc': 'Pkg2 part A: restorefactory_DeleteComponent.sh (factory reset + re-enable)'},
    133: {'pkg': 2, 'role': 'telnet',
          'desc': 'Pkg2 part B: run.sh (Telnet+SSH enabler)'},
    134: {'pkg': 3, 'role': 'full',
          'desc': 'Pkg3 part A: equipment.tar.gz (1.7 MB) + TelnetEnable + duit9rr.sh'},
    135: {'pkg': 3, 'role': 'telnet',
          'desc': 'Pkg3 part B: run.sh (Telnet+SSH enabler) — identical to BIN133'},
}


def parse_hwnp_header(data):
    """Parse HWNP header and return metadata dict."""
    if data[:4] != b'HWNP':
        return None

    raw_sz = struct.unpack('>I', data[4:8])[0]
    raw_crc = struct.unpack('>I', data[8:12])[0]
    hdr_crc = struct.unpack('<I', data[16:20])[0]
    item_counts = struct.unpack('<I', data[20:24])[0]
    prod_list_sz = struct.unpack('<H', data[26:28])[0]
    item_sz = struct.unpack('<I', data[28:32])[0]

    prod_data = data[36:36 + prod_list_sz]
    prod_str = prod_data.split(b'\x00')[0].decode('ascii', errors='replace')
    equip_ids = [x for x in prod_str.split('|') if x]

    items_start = 36 + prod_list_sz
    items = []
    for i in range(item_counts):
        off = items_start + i * item_sz
        item = data[off:off + item_sz]
        d_off = struct.unpack('<I', item[8:12])[0]
        d_sz = struct.unpack('<I', item[12:16])[0]
        path = item[16:272].split(b'\x00')[0].decode('ascii', errors='replace')
        section = item[272:288].split(b'\x00')[0].decode('ascii', errors='replace')
        version = item[288:352].split(b'\x00')[0].decode('ascii', errors='replace')
        policy = struct.unpack('<I', item[352:356])[0]
        crc = struct.unpack('<I', item[4:8])[0]
        items.append({
            'index': i, 'path': path, 'section': section, 'version': version,
            'data_offset': d_off, 'data_size': d_sz, 'crc32': crc, 'policy': policy,
        })

    return {
        'raw_size': raw_sz, 'raw_crc32': raw_crc, 'hdr_crc32': hdr_crc,
        'item_count': item_counts, 'prod_list_size': prod_list_sz, 'item_size': item_sz,
        'equipment_ids': equip_ids, 'items': items,
    }


def extract_packages(exe_path, output_dir):
    """Extract all BIN resources from the EXE."""
    print(f'Loading {exe_path}...')
    pe = pefile.PE(exe_path)
    os.makedirs(output_dir, exist_ok=True)

    extracted = {}
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not rsrc_type.name or str(rsrc_type.name) != 'BIN':
            continue
        for rsrc_id in rsrc_type.directory.entries:
            bid = rsrc_id.struct.Id
            if bid not in BIN_INFO:
                continue
            for rsrc_lang in rsrc_id.directory.entries:
                rva = rsrc_lang.data.struct.OffsetToData
                size = rsrc_lang.data.struct.Size
                raw_data = pe.get_data(rva, size)

                info = BIN_INFO[bid]
                filename = f'BIN{bid}_pkg{info["pkg"]}_{info["role"]}.bin'
                filepath = os.path.join(output_dir, filename)

                with open(filepath, 'wb') as f:
                    f.write(raw_data)

                hwnp = parse_hwnp_header(raw_data)
                extracted[bid] = {
                    'filename': filename, 'size': size,
                    'hwnp': hwnp, 'info': info,
                }

                print(f'\n  BIN {bid}: {filename} ({size:,} bytes)')
                print(f'    {info["desc"]}')
                if hwnp:
                    print(f'    HWNP: {hwnp["item_count"]} items, '
                          f'{len(hwnp["equipment_ids"])} equipment IDs')
                    for item in hwnp['items']:
                        name = item['path'].split('/')[-1]
                        pol = ' [AUTO-EXEC]' if item['policy'] == 2 else ''
                        print(f'      [{item["index"]}] {name} '
                              f'({item["data_size"]:,} B){pol}')

    # Also extract individual scripts
    scripts_dir = os.path.join(output_dir, 'scripts')
    os.makedirs(scripts_dir, exist_ok=True)
    print(f'\nExtracting shell scripts to {scripts_dir}/:')
    for bid, info in sorted(extracted.items()):
        hwnp = info['hwnp']
        if not hwnp:
            continue
        pkg_file = os.path.join(output_dir, info['filename'])
        with open(pkg_file, 'rb') as f:
            pkg_data = f.read()
        for item in hwnp['items']:
            if item['path'].endswith('.sh') and item['data_size'] > 0:
                d_off = item['data_offset']
                d_sz = item['data_size']
                if d_off + d_sz <= len(pkg_data):
                    script_data = pkg_data[d_off:d_off + d_sz]
                    script_name = item['path'].split('/')[-1]
                    out_name = f'BIN{bid}_{script_name}'
                    out_path = os.path.join(scripts_dir, out_name)
                    with open(out_path, 'wb') as f:
                        f.write(script_data)
                    print(f'  {out_name} ({d_sz:,} B)')

    print(f'\nExtracted {len(extracted)} packages to {output_dir}/')
    return extracted


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <input.exe> [output_dir]')
        sys.exit(1)

    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'firmware_packages'
    extract_packages(exe_path, output_dir)


if __name__ == '__main__':
    main()
