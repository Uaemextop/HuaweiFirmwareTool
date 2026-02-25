#!/usr/bin/env python3
"""
modify_pkg3.py - Modify Enable Pkg 3 in ONT_V100R002C00SPC253_EN.exe

Replaces the auto-execute script in BIN134 (Pkg3 part A) with the
restorefactory_DeleteComponent.sh from BIN132 (Pkg2 part A), so that
Enable Pkg 3 performs a factory reset + Telnet/SSH re-enable instead
of the default duit9rr.sh behavior.

How Enable Packages work:
  - The EXE embeds 6 HWNP firmware packages as PE BIN resources (130-135)
  - Each Enable Pkg uses TWO packages sent sequentially via OBSC UDP broadcast
  - The packages are NOT encrypted — raw HWNP data in PE resources
  - The handler sends Part A first, then Part B
  - Items with policy=2 are auto-executed as shell scripts on the ONT device

Usage:
    pip install pefile
    python3 modify_pkg3.py <input.exe> <output.exe>
"""
import struct
import sys
import zlib

try:
    import pefile
except ImportError:
    print('Error: pefile is required.  pip install pefile')
    sys.exit(1)


def crc32(data):
    """Calculate CRC32 matching the Huawei firmware tool convention."""
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_hwnp(data):
    """Parse HWNP package into header, product list, items, and item data."""
    if data[:4] != b'HWNP':
        raise ValueError('Not a HWNP package')

    raw_sz = struct.unpack('>I', data[4:8])[0]
    item_counts = struct.unpack('<I', data[20:24])[0]
    prod_list_sz = struct.unpack('<H', data[26:28])[0]
    item_sz = struct.unpack('<I', data[28:32])[0]

    prod_list = data[36:36 + prod_list_sz]
    items_start = 36 + prod_list_sz
    hdr_region_sz = items_start + item_counts * item_sz

    items = []
    for i in range(item_counts):
        off = items_start + i * item_sz
        raw_item = bytearray(data[off:off + item_sz])
        d_off = struct.unpack('<I', raw_item[8:12])[0]
        d_sz = struct.unpack('<I', raw_item[12:16])[0]
        path = raw_item[16:272].split(b'\x00')[0].decode('ascii', errors='replace')

        item_data = data[d_off:d_off + d_sz] if d_sz > 0 and d_off > 0 else b''
        items.append({
            'raw': raw_item,
            'path': path,
            'data': item_data,
            'data_offset': d_off,
            'data_size': d_sz,
        })

    return {
        'header': bytearray(data[:36]),
        'prod_list': prod_list,
        'item_sz': item_sz,
        'item_counts': item_counts,
        'items': items,
        'hdr_region_sz': hdr_region_sz,
    }


def rebuild_hwnp(parsed, new_items_data=None):
    """Rebuild HWNP package from parsed structure with optional item data replacements.

    new_items_data: dict mapping item index to new data bytes
    """
    if new_items_data is None:
        new_items_data = {}

    header = bytearray(parsed['header'])
    prod_list = parsed['prod_list']
    item_sz = parsed['item_sz']
    items = parsed['items']

    # Calculate header region size
    items_start = 36 + len(prod_list)
    hdr_region_sz = items_start + len(items) * item_sz

    # Build data region: concatenate all item data with updated offsets
    data_parts = []
    current_offset = hdr_region_sz
    updated_items = []

    for i, item in enumerate(items):
        item_raw = bytearray(item['raw'])
        item_data = new_items_data.get(i, item['data'])

        if len(item_data) == 0:
            struct.pack_into('<I', item_raw, 8, 0)   # data_off = 0
            struct.pack_into('<I', item_raw, 12, 0)   # data_sz = 0
            struct.pack_into('<I', item_raw, 4, 0)    # item_crc32 = 0
        else:
            struct.pack_into('<I', item_raw, 8, current_offset)
            struct.pack_into('<I', item_raw, 12, len(item_data))
            struct.pack_into('<I', item_raw, 4, crc32(item_data))
            data_parts.append(item_data)
            current_offset += len(item_data)

        updated_items.append(item_raw)

    # Calculate raw_sz (total data size) and raw_crc32
    all_data = b''.join(data_parts)
    raw_sz = len(all_data)

    # Calculate raw_crc32 using crc32_combine approach (sequential CRC of all item data)
    raw_crc = 0
    for i, item in enumerate(items):
        item_data = new_items_data.get(i, item['data'])
        if len(item_data) > 0:
            raw_crc = zlib.crc32(item_data, raw_crc) & 0xFFFFFFFF

    # Update header
    struct.pack_into('>I', header, 4, raw_sz)       # raw_sz (big-endian)
    struct.pack_into('>I', header, 8, raw_crc)       # raw_crc32 (big-endian)

    # Build header region (header + prod_list + items)
    hdr_region = bytes(header) + prod_list
    for item_raw in updated_items:
        hdr_region += bytes(item_raw)

    # Calculate hdr_sz and hdr_crc32
    struct.pack_into('<I', header, 12, len(hdr_region))

    # Zero out hdr_crc32 field for calculation
    hdr_for_crc = bytearray(hdr_region)
    hdr_for_crc[16:20] = b'\x00\x00\x00\x00'
    hdr_crc = crc32(bytes(hdr_for_crc))
    struct.pack_into('<I', header, 16, hdr_crc)

    # Rebuild final package
    final_hdr_region = bytes(header) + prod_list
    for item_raw in updated_items:
        final_hdr_region += bytes(item_raw)

    return final_hdr_region + all_data


def get_bin_resource(pe, bin_id):
    """Get raw data for a BIN resource by ID."""
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if rsrc_type.name and str(rsrc_type.name) == 'BIN':
            for rsrc_id in rsrc_type.directory.entries:
                if rsrc_id.struct.Id == bin_id:
                    for rsrc_lang in rsrc_id.directory.entries:
                        rva = rsrc_lang.data.struct.OffsetToData
                        size = rsrc_lang.data.struct.Size
                        return pe.get_data(rva, size), rva, size, rsrc_lang
    return None, None, None, None


def replace_bin_resource_inplace(file_data, pe, bin_id, new_data):
    """Replace a BIN resource in-place (new data must be <= old size)."""
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if rsrc_type.name and str(rsrc_type.name) == 'BIN':
            for rsrc_id in rsrc_type.directory.entries:
                if rsrc_id.struct.Id == bin_id:
                    for rsrc_lang in rsrc_id.directory.entries:
                        rva = rsrc_lang.data.struct.OffsetToData
                        old_size = rsrc_lang.data.struct.Size
                        file_offset = pe.get_offset_from_rva(rva)

                        if len(new_data) > old_size:
                            return False
                        file_data[file_offset:file_offset + old_size] = (
                            new_data + b'\x00' * (old_size - len(new_data)))
                        entry_off = rsrc_lang.data.struct.get_file_offset()
                        struct.pack_into('<I', file_data, entry_off + 4, len(new_data))
                        return True
    return False


def expand_rsrc_and_replace(file_data, pe, bin_id, new_data):
    """Expand .rsrc section to accommodate a larger resource, shifting .reloc.

    Steps:
    1. Find BIN resource's current location in .rsrc
    2. Insert padding into file to expand .rsrc raw size
    3. Move .reloc section forward
    4. Write new resource data at old location (expanding into freed space)
    5. Update all PE headers (.rsrc size, .reloc pointers, data directories, etc.)
    6. Update RVAs of all resources whose file offsets shifted
    """
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment

    rsrc_section = reloc_section = None
    for s in pe.sections:
        if s.Name.startswith(b'.rsrc'):
            rsrc_section = s
        elif s.Name.startswith(b'.reloc'):
            reloc_section = s

    if rsrc_section is None:
        raise ValueError('Cannot find .rsrc section')

    # Find the resource entry
    target_rva = target_size = target_file_off = None
    target_entry_off = None
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if rsrc_type.name and str(rsrc_type.name) == 'BIN':
            for rsrc_id in rsrc_type.directory.entries:
                if rsrc_id.struct.Id == bin_id:
                    for rsrc_lang in rsrc_id.directory.entries:
                        target_rva = rsrc_lang.data.struct.OffsetToData
                        target_size = rsrc_lang.data.struct.Size
                        target_file_off = pe.get_offset_from_rva(target_rva)
                        target_entry_off = rsrc_lang.data.struct.get_file_offset()

    if target_file_off is None:
        raise ValueError(f'BIN {bin_id} not found')

    size_diff = len(new_data) - target_size
    if size_diff <= 0:
        return replace_bin_resource_inplace(file_data, pe, bin_id, new_data)

    # Calculate expansion needed (aligned to file alignment)
    expand_bytes = (size_diff + file_align - 1) & ~(file_align - 1)
    insert_point = target_file_off + target_size  # Insert right after old resource

    print(f'  Expanding .rsrc by {expand_bytes} bytes at 0x{insert_point:x}')

    # Insert expansion bytes at the end of the old resource data
    file_data[insert_point:insert_point] = b'\x00' * expand_bytes

    # Write the new (larger) resource data at the old location
    file_data[target_file_off:target_file_off + len(new_data)] = new_data

    # Update the target resource directory entry: size
    struct.pack_into('<I', file_data, target_entry_off + 4, len(new_data))

    # Update RVAs of ALL resources whose file offsets are >= insert_point
    # These got shifted by expand_bytes
    pe_offset = struct.unpack_from('<I', file_data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', file_data, pe_offset + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', file_data, pe_offset + 20)[0]
    sections_offset = pe_offset + 24 + opt_hdr_size

    rsrc_va = rsrc_section.VirtualAddress
    rsrc_raw_ptr = rsrc_section.PointerToRawData

    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for rsrc_id in rsrc_type.directory.entries:
            for rsrc_lang in rsrc_id.directory.entries:
                r_rva = rsrc_lang.data.struct.OffsetToData
                r_foff = pe.get_offset_from_rva(r_rva)

                if r_foff >= insert_point and rsrc_lang.data.struct.get_file_offset() != target_entry_off:
                    new_rva = r_rva + expand_bytes
                    entry_off = rsrc_lang.data.struct.get_file_offset()
                    # Entry offsets in the resource directory are also shifted if they come
                    # after the insert point. But the resource directory is at the start of
                    # .rsrc so its entries aren't shifted.
                    actual_entry_off = entry_off
                    if entry_off >= insert_point:
                        actual_entry_off = entry_off + expand_bytes

                    struct.pack_into('<I', file_data, actual_entry_off, new_rva)
                    type_name = rsrc_type.name or rsrc_type.struct.Id
                    bid_name = rsrc_id.name or rsrc_id.struct.Id
                    print(f'  Updated {type_name}/{bid_name}: RVA 0x{r_rva:x} -> 0x{new_rva:x}')

    # Update section headers
    for i in range(num_sections):
        s_off = sections_offset + i * 40
        s_name = file_data[s_off:s_off + 8]

        if s_name.startswith(b'.rsrc'):
            old_raw = struct.unpack_from('<I', file_data, s_off + 16)[0]
            old_vs = struct.unpack_from('<I', file_data, s_off + 8)[0]
            struct.pack_into('<I', file_data, s_off + 16, old_raw + expand_bytes)
            struct.pack_into('<I', file_data, s_off + 8, old_vs + expand_bytes)
            print(f'  .rsrc: RawSize 0x{old_raw:x} -> 0x{old_raw+expand_bytes:x}')

        elif s_name.startswith(b'.reloc'):
            old_ptr = struct.unpack_from('<I', file_data, s_off + 20)[0]
            old_va = struct.unpack_from('<I', file_data, s_off + 12)[0]
            struct.pack_into('<I', file_data, s_off + 20, old_ptr + expand_bytes)
            new_va = (old_va + expand_bytes + sect_align - 1) & ~(sect_align - 1)
            struct.pack_into('<I', file_data, s_off + 12, new_va)
            print(f'  .reloc: RawPtr 0x{old_ptr:x} -> 0x{old_ptr+expand_bytes:x}, '
                  f'VA 0x{old_va:x} -> 0x{new_va:x}')

            # Update PE data directory for relocations (entry 5)
            reloc_dd_off = pe_offset + 24 + 136
            struct.pack_into('<I', file_data, reloc_dd_off, new_va)

    # Update SizeOfImage
    size_of_image_off = pe_offset + 24 + 56
    old_soi = struct.unpack_from('<I', file_data, size_of_image_off)[0]
    new_soi = (old_soi + expand_bytes + sect_align - 1) & ~(sect_align - 1)
    struct.pack_into('<I', file_data, size_of_image_off, new_soi)
    print(f'  SizeOfImage: 0x{old_soi:x} -> 0x{new_soi:x}')

    return True


def fixup_pe_checksum(file_data):
    """Recalculate and update the PE checksum."""
    pe_offset = struct.unpack_from('<I', file_data, 0x3C)[0]
    checksum_offset = pe_offset + 88

    file_data[checksum_offset:checksum_offset + 4] = b'\x00\x00\x00\x00'

    checksum = 0
    size = len(file_data)
    for i in range(0, size & ~1, 2):
        val = struct.unpack_from('<H', file_data, i)[0]
        checksum += val
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    if size % 2:
        checksum += file_data[-1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += size

    struct.pack_into('<I', file_data, checksum_offset, checksum & 0xFFFFFFFF)


def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <input.exe> <output.exe>')
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f'Modifying Pkg3 in {input_path}...')

    with open(input_path, 'rb') as f:
        file_data = bytearray(f.read())

    pe = pefile.PE(data=bytes(file_data))

    # Step 1: Extract restorefactory_DeleteComponent.sh from BIN132
    print('\n1. Extracting factory reset script from BIN132...')
    bin132_data, _, _, _ = get_bin_resource(pe, 132)
    if bin132_data is None:
        print('  ERROR: BIN132 not found')
        sys.exit(1)

    parsed_132 = parse_hwnp(bin132_data)
    factory_script = None
    for item in parsed_132['items']:
        if 'restorefactory' in item['path']:
            factory_script = item['data']
            print(f'  Found: {item["path"]} ({len(factory_script)} bytes)')
            break

    if factory_script is None:
        print('  ERROR: restorefactory script not found in BIN132')
        sys.exit(1)

    # Step 2: Parse BIN134 (Pkg3 part A)
    print('\n2. Parsing BIN134 (Pkg3 part A)...')
    bin134_data, bin134_rva, bin134_size, _ = get_bin_resource(pe, 134)
    if bin134_data is None:
        print('  ERROR: BIN134 not found')
        sys.exit(1)

    parsed_134 = parse_hwnp(bin134_data)
    print(f'  Original: {len(bin134_data)} bytes, {parsed_134["item_counts"]} items')
    for i, item in enumerate(parsed_134['items']):
        policy_str = ' [AUTO-EXEC]' if struct.unpack('<I', item['raw'][352:356])[0] == 2 else ''
        print(f'    [{i}] {item["path"]} ({item["data_size"]} B){policy_str}')

    # Step 3: Replace duit9rr.sh with restorefactory script
    print('\n3. Replacing duit9rr.sh with restorefactory_DeleteComponent.sh...')
    script_idx = None
    for i, item in enumerate(parsed_134['items']):
        if 'duit9rr.sh' in item['path']:
            script_idx = i
            break

    if script_idx is None:
        print('  ERROR: duit9rr.sh not found in BIN134')
        sys.exit(1)

    old_size = parsed_134['items'][script_idx]['data_size']
    print(f'  Old script: {old_size} bytes')
    print(f'  New script: {len(factory_script)} bytes')

    # Update the item path to reflect the new script
    new_path = b'file:/tmp/restorefactory_DeleteComponent.sh'
    item_raw = parsed_134['items'][script_idx]['raw']
    # Clear old path and write new one
    item_raw[16:272] = b'\x00' * 256
    item_raw[16:16 + len(new_path)] = new_path

    # Step 4: Rebuild BIN134 with new script
    print('\n4. Rebuilding HWNP package...')
    new_items = {script_idx: factory_script}
    new_bin134 = rebuild_hwnp(parsed_134, new_items)
    print(f'  New package: {len(new_bin134)} bytes (was {len(bin134_data)})')

    # Verify the rebuilt package
    verify = parse_hwnp(new_bin134)
    for i, item in enumerate(verify['items']):
        policy_str = ' [AUTO-EXEC]' if struct.unpack('<I', item['raw'][352:356])[0] == 2 else ''
        print(f'    [{i}] {item["path"]} ({item["data_size"]} B){policy_str}')

    # Step 5: Replace BIN134 resource in EXE
    print('\n5. Replacing BIN134 in EXE...')
    if len(new_bin134) <= len(bin134_data):
        success = replace_bin_resource_inplace(file_data, pe, 134, new_bin134)
    else:
        success = expand_rsrc_and_replace(file_data, pe, 134, new_bin134)
    if not success:
        print('  ERROR: Failed to replace BIN134')
        sys.exit(1)
    print('  Resource replaced successfully')

    # Step 6: Fix PE checksum
    print('\n6. Fixing PE checksum...')
    fixup_pe_checksum(file_data)

    # Step 7: Write output
    with open(output_path, 'wb') as f:
        f.write(file_data)

    print(f'\nDone! Modified EXE written to {output_path}')
    print(f'  Pkg3 now performs factory reset + Telnet/SSH re-enable')


if __name__ == '__main__':
    main()
