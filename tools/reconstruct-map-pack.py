#!/usr/bin/env python3
"""Reconstruct an exact public-data PMTiles/ZIP pack from a small framing seed.

Python standard library only. No app code, user data, keys or diagnostics are
needed. All outputs are withheld until the PMTiles, joined ZIP and every chunk
match their independently pinned SHA-256 values.
"""
import argparse
import bisect
import concurrent.futures
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zipfile import ZIP_STORED, ZipFile

BLOCK = 1024 * 1024
SOURCE = 'https://build.protomaps.com/20261006.pmtiles'
MAP_SHA = '8c8522164230aaa8bc94f5ee77ece20e72c48389860026b40518fa9331e63be2'
MAP_SIZE = 3123603053
ZIP_SHA = '453a8a4479c688f9a67c53253e7674dc3ce57f9999fe1affa60aeee888db52fc'
ZIP_SIZE = 3324193120
SOURCE_HEADER_SHA = 'f70003cd9f910e7bbf989d7bac3036c0a32fe69a863cc912ccbfc7871a56e8d1'
FIELDS = ('root_offset', 'root_length', 'metadata_offset', 'metadata_length',
          'leaf_offset', 'leaf_length', 'tile_offset', 'tile_length',
          'addressed_tiles', 'tile_entries', 'tile_contents')


def check(condition, message):
    if not condition:
        raise ValueError(message)


def log(message):
    print(time.strftime('%H:%M:%S'), message, flush=True)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(BLOCK):
            digest.update(block)
    return digest.hexdigest()


def copy_range(source, destination, offset, length):
    digest = hashlib.sha256()
    with Path(source).open('rb') as stream, Path(destination).open('wb') as out:
        stream.seek(offset)
        remaining = length
        while remaining:
            block = stream.read(min(BLOCK, remaining))
            check(block, 'Truncated framing source')
            out.write(block)
            digest.update(block)
            remaining -= len(block)
    return {'size': length, 'sha256': digest.hexdigest()}


def header(data):
    check(len(data) == 127 and data[:8] == b'PMTiles\x03', 'Expected PMTiles v3')
    check(data[97:100] == bytes((2, 2, 1)), 'Expected gzip directories and gzip MVT tiles')
    result = dict(zip(FIELDS, struct.unpack_from('<11Q', data, 8)))
    result['bytes'] = data
    return result


def varints(data):
    at = 0
    while at < len(data):
        value = shift = 0
        while True:
            check(at < len(data) and shift <= 63, 'Truncated or excessive directory varint')
            byte = data[at]
            at += 1
            value |= (byte & 127) << shift
            if byte < 128:
                break
            shift += 7
        yield value


def directory(data):
    values = iter(varints(gzip.decompress(data)))
    try:
        count = next(values)
        check(0 < count <= 5_000_000, 'Invalid directory entry count')
        ids = []
        current = 0
        for _ in range(count):
            current += next(values)
            ids.append(current)
        runs = [next(values) for _ in range(count)]
        lengths = [next(values) for _ in range(count)]
        offsets = []
        for number in range(count):
            encoded = next(values)
            check(encoded > 0 or number > 0, 'Invalid first directory offset')
            offsets.append(offsets[-1] + lengths[number - 1] if encoded == 0 else encoded - 1)
        check(next(values, None) is None, 'Extra directory data')
    except StopIteration as error:
        raise ValueError('Truncated PMTiles directory') from error
    entries = list(zip(ids, runs, lengths, offsets))
    check(all(e[2] > 0 and e[3] >= 0 for e in entries), 'Invalid directory entry')
    check(all(ids[i] < ids[i+1] for i in range(len(ids)-1)), 'Unordered directory IDs')
    return entries


def contents_from_prefix(prefix):
    data = Path(prefix).read_bytes()
    layout = header(data[:127])
    check(layout['tile_offset'] == len(data), 'Seed prefix must stop immediately before tile data')
    def region(offset, length):
        check(0 <= offset <= offset + length <= len(data), 'Directory outside seed prefix')
        return data[offset:offset+length]
    root = directory(region(layout['root_offset'], layout['root_length']))
    entries = []
    for entry in root:
        if entry[1]:
            entries.append(entry)
        else:
            check(entry[3] + entry[2] <= layout['leaf_length'], 'Leaf outside leaf section')
            entries.extend(directory(region(layout['leaf_offset'] + entry[3], entry[2])))
    entries.sort()
    check(len(entries) == layout['tile_entries'], 'Incorrect target directory entry count')
    check(sum(e[1] for e in entries) == layout['addressed_tiles'], 'Incorrect addressed tile count')
    check(all(e[1] > 0 for e in entries), 'Nested leaf directory unsupported')
    check(all(entries[i][0] + entries[i][1] <= entries[i+1][0]
              for i in range(len(entries)-1)), 'Overlapping target tile IDs')
    unique = {}
    for entry in entries:
        old = unique.setdefault(entry[3], entry)
        check(old[2] == entry[2], 'Inconsistent shared tile content length')
    contents = sorted(unique.values(), key=lambda e: e[3])
    check(len(contents) == layout['tile_contents'], 'Incorrect target tile content count')
    check(contents and contents[0][3] == 0, 'Target tile content must start at zero')
    check(all(contents[i][3] + contents[i][2] == contents[i+1][3]
              for i in range(len(contents)-1)), 'Target tile contents must be contiguous')
    check(contents[-1][3] + contents[-1][2] == layout['tile_length'], 'Wrong target tile length')
    return layout, contents


class RangeFetcher:
    """urllib uses HTTP/1.1; retries exact 206 ranges without unbounded reads."""
    def __init__(self, url=SOURCE, cache=None, attempts=8):
        self.url = url
        self.cache = Path(cache) if cache else None
        self.attempts = attempts
        self.total_size = None
        if self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)

    def fetch(self, start, length, cache=False):
        check(start >= 0 and 0 < length <= 32 * BLOCK, 'Invalid bounded source range')
        target = self.cache / f'{start}-{length}.bin' if cache and self.cache else None
        if target and target.exists() and target.stat().st_size == length:
            return target.read_bytes()
        for attempt in range(self.attempts):
            try:
                request = Request(self.url, headers={
                    'Range': f'bytes={start}-{start+length-1}',
                    'Accept-Encoding': 'identity',
                    'User-Agent': 'public-osm-pack-reconstruction/1'})
                with urlopen(request, timeout=120) as response:
                    check(response.status == 206, 'Source did not return HTTP 206')
                    match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                    check(match and int(match[1]) == start and int(match[2]) == start+length-1,
                          'Source returned a different byte range')
                    total = int(match[3])
                    check(start + length <= total, 'Source range exceeds file')
                    if self.total_size is not None:
                        check(self.total_size == total, 'Source file changed during reconstruction')
                    self.total_size = total
                    data = response.read(length+1)
                    check(len(data) == length, 'Truncated or excessive source range response')
                if target:
                    temporary = target.with_suffix('.partial')
                    temporary.write_bytes(data)
                    temporary.replace(target)
                return data
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
                if attempt + 1 == self.attempts:
                    raise RuntimeError(f'Range {start}+{length} failed after {self.attempts} attempts') from error
                time.sleep(min(15, 2 ** attempt))
        raise RuntimeError('Unreachable range retry')


def match_entries(source_entries, wanted):
    """Map representative target IDs to the exact original compressed content."""
    ids = [entry[0] for entry in source_entries]
    mapped = []
    for entry in wanted:
        position = bisect.bisect_right(ids, entry[0]) - 1
        check(position >= 0, f'Target tile {entry[0]} absent in source')
        original = source_entries[position]
        check(original[1] > 0 and original[0] <= entry[0] < original[0] + original[1],
              f'Target tile {entry[0]} absent in source run')
        check(original[2] == entry[2], f'Target tile {entry[0]} compressed length changed')
        mapped.append((original[3], entry[3], entry[2]))
    return mapped


def group_ranges(mapped, maximum=16*BLOCK, gap=4096):
    """Merge adjacent/overlapping ranges, also tolerating tiny source gaps.

Destinations need not be adjacent. A shared original content may be written to
multiple target positions; every assignment retains its precise byte offset.
"""
    groups = []
    for source, destination, length in sorted(mapped):
        if groups and source <= groups[-1][0] + groups[-1][1] + gap and max(
                groups[-1][0] + groups[-1][1], source + length) - groups[-1][0] <= maximum:
            start, size, assignments = groups[-1]
            groups[-1] = (start, max(start+size, source+length)-start, assignments)
            assignments.append((source-start, destination, length))
        else:
            check(length <= maximum, 'Single tile exceeds range cap')
            groups.append((source, length, [(0, destination, length)]))
    return groups


def source_mapping(fetcher, source, wanted, workers):
    root = directory(fetcher.fetch(source['root_offset'], source['root_length'], cache=True))
    wanted = sorted(wanted)
    ids = [entry[0] for entry in wanted]
    mapped = []
    requests = []
    for number, entry in enumerate(root):
        lower = bisect.bisect_left(ids, entry[0])
        upper = bisect.bisect_left(ids, root[number+1][0]) if number+1 < len(root) else len(ids)
        if lower == upper:
            continue
        if entry[1]:
            mapped.extend(match_entries([entry], wanted[lower:upper]))
        else:
            check(entry[3] + entry[2] <= source['leaf_length'], 'Source leaf outside section')
            requests.append((entry, wanted[lower:upper]))
    log(f'Mapping {len(wanted):,} unique target contents through {len(requests)} source leaves')
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetcher.fetch, source['leaf_offset']+entry[3], entry[2], True): needed
                   for entry, needed in requests}
        for future in concurrent.futures.as_completed(futures):
            mapped.extend(match_entries(directory(future.result()), futures[future]))
    check(len(mapped) == len(wanted), 'Not every target content was mapped')
    check(len({entry[1] for entry in mapped}) == len(wanted), 'Duplicate target content mapping')
    groups = group_ranges(mapped)
    log(f'Fetching {len(groups):,} bounded ranges, {sum(g[1] for g in groups):,} source bytes')
    return groups


def reconstruct_map(prefix, output, fetcher, workers):
    layout, wanted = contents_from_prefix(prefix)
    source_bytes = fetcher.fetch(0, 127, cache=True)
    check(hashlib.sha256(source_bytes).hexdigest() == SOURCE_HEADER_SHA, 'Pinned source header changed')
    source = header(source_bytes)
    with Path(prefix).open('rb') as stream:
        stream.seek(layout['metadata_offset'])
        target_metadata = stream.read(layout['metadata_length'])
    check(target_metadata == fetcher.fetch(source['metadata_offset'], source['metadata_length'], cache=True),
          'Pinned source metadata differs from extraction')
    groups = source_mapping(fetcher, source, wanted, workers)
    check(layout['tile_offset'] + layout['tile_length'] == MAP_SIZE, 'Wrong target map size')
    output = Path(output)
    check(not output.exists(), 'Refusing to replace an existing map output')
    shutil.copyfile(prefix, output)
    done = 0
    start = time.monotonic()
    with output.open('r+b', buffering=0) as file:
        file.truncate(MAP_SIZE)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {}
            cursor = iter(groups)
            for _ in range(workers*2):
                group = next(cursor, None)
                if group:
                    pending[pool.submit(fetcher.fetch, source['tile_offset'] + group[0], group[1])] = group
            while pending:
                finished, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in finished:
                    _, size, assignments = pending.pop(future)
                    data = future.result()
                    for relative, destination, length in assignments:
                        file.seek(layout['tile_offset'] + destination)
                        check(file.write(memoryview(data)[relative:relative+length]) == length, 'Short tile write')
                    done += size
                    log(f'Source ranges {done:,} bytes; {done/max(1,time.monotonic()-start)/1e6:.1f} MB/s')
                    del data
                    group = next(cursor, None)
                    if group:
                        pending[pool.submit(fetcher.fetch, source['tile_offset']+group[0], group[1])] = group
        os.fsync(file.fileno())
    check(output.stat().st_size == MAP_SIZE and digest_file(output) == MAP_SHA, 'Reconstructed PMTiles SHA-256 failed')
    log(f'PMTiles verified: {MAP_SHA}')


def assemble_parts(paths, index, directory_path, write=True):
    """Frame the exact ZIP while hashing its parts, without a joined ZIP copy."""
    parts = index['parts']
    output = Path(directory_path)
    output.mkdir(parents=True, exist_ok=True)
    joined = hashlib.sha256()
    total = number = part_bytes = 0
    digest = hashlib.sha256()
    temporary_paths = []
    stream = None
    try:
        for path in paths:
            with Path(path).open('rb') as source:
                while block := source.read(BLOCK):
                    at = 0
                    while at < len(block):
                        check(number < len(parts), 'Framing exceeds expected archive size')
                        if part_bytes == 0 and write:
                            temporary = output / (parts[number]['name'] + '.partial')
                            check(not temporary.exists() and not (output / parts[number]['name']).exists(),
                                  'Refusing to overwrite an existing part')
                            temporary_paths.append(temporary)
                            stream = temporary.open('wb')
                        count = min(len(block)-at, parts[number]['size']-part_bytes)
                        piece = memoryview(block)[at:at+count]
                        if stream:
                            stream.write(piece)
                        digest.update(piece)
                        joined.update(piece)
                        part_bytes += count
                        total += count
                        at += count
                        if part_bytes == parts[number]['size']:
                            if stream:
                                stream.close()
                                stream = None
                            check(digest.hexdigest() == parts[number]['sha256'],
                                  f'Part {number+1} SHA-256 failed')
                            number += 1
                            part_bytes = 0
                            digest = hashlib.sha256()
        check(number == len(parts) and part_bytes == 0, 'Truncated framed ZIP')
        check(total == index['archive']['size'] and joined.hexdigest() == index['archive']['sha256'],
              'Framed ZIP SHA-256 failed')
        if write:
            for temporary, spec in zip(temporary_paths, parts):
                temporary.replace(output / spec['name'])
        return total, joined.hexdigest()
    finally:
        if stream:
            stream.close()
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)


def make_seed(map_path, zip_path, index_path, output):
    map_path, zip_path = Path(map_path), Path(zip_path)
    check(map_path.stat().st_size == MAP_SIZE and digest_file(map_path) == MAP_SHA, 'Original map SHA-256 failed')
    check(zip_path.stat().st_size == ZIP_SIZE and digest_file(zip_path) == ZIP_SHA, 'Original ZIP SHA-256 failed')
    index = json.loads(Path(index_path).read_text())
    check(index['archive']['size'] == ZIP_SIZE and index['archive']['sha256'] == ZIP_SHA, 'Wrong original index')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with map_path.open('rb') as stream:
        layout = header(stream.read(127))
    with ZipFile(zip_path) as archive:
        entry = archive.getinfo('gb-basemap.pmtiles')
        check(entry.compress_type == ZIP_STORED and entry.file_size == MAP_SIZE and entry.compress_size == MAP_SIZE,
              'Seed requires the exact uncompressed ZIP map entry')
        with zip_path.open('rb') as stream:
            stream.seek(entry.header_offset)
            local = stream.read(30)
        check(local[:4] == b'PK\x03\x04', 'Missing ZIP local header')
        name_bytes, extra_bytes = struct.unpack_from('<HH', local, 26)
        data_offset = entry.header_offset + 30 + name_bytes + extra_bytes
    specs = {}
    specs['map-prefix.bin'] = copy_range(map_path, output/'map-prefix.bin', 0, layout['tile_offset'])
    specs['zip-prefix.bin'] = copy_range(zip_path, output/'zip-prefix.bin', 0, data_offset)
    suffix_offset = data_offset + MAP_SIZE
    specs['zip-suffix.bin'] = copy_range(zip_path, output/'zip-suffix.bin', suffix_offset, ZIP_SIZE-suffix_offset)
    recipe = {'format': 1, 'source': SOURCE, 'sourceHeaderSha256': SOURCE_HEADER_SHA,
              'map': {'name': 'gb-basemap.pmtiles', 'size': MAP_SIZE, 'sha256': MAP_SHA},
              'frames': specs, 'index': index}
    (output/'recipe.json').write_text(json.dumps(recipe, indent=2)+'\n')
    # The files are already compact binary data. Compression level 1 is bounded
    # memory and saves bandwidth without taking minutes on source data.
    target = output/'drover-map-reconstruction-seed.tar.gz'
    with target.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=1) as zipped:
        with tarfile.open(fileobj=zipped, mode='w|') as archive:
            for name in ('recipe.json', *specs):
                info = archive.gettarinfo(str(output/name), arcname=name)
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ''
                with (output/name).open('rb') as stream:
                    archive.addfile(info, stream)
    log(f'Seed size={target.stat().st_size} SHA-256={digest_file(target)}')
    return recipe


def unpack_seed(seed, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    required = {'recipe.json', 'map-prefix.bin', 'zip-prefix.bin', 'zip-suffix.bin'}
    seen = set()
    with tarfile.open(seed, 'r|gz') as archive:
        for member in archive:
            check(member.name in required and member.name not in seen and member.isfile(), 'Unexpected seed member')
            check(member.size <= 250_000_000, 'Excessive seed member size')
            seen.add(member.name)
            target = destination/member.name
            check(not target.exists(), 'Refusing to overwrite seed files')
            with archive.extractfile(member) as stream, target.open('wb') as out:
                shutil.copyfileobj(stream, out, BLOCK)
    check(seen == required, 'Missing seed member')
    recipe = json.loads((destination/'recipe.json').read_text())
    check(recipe.get('format') == 1 and recipe.get('source') == SOURCE and
          recipe.get('sourceHeaderSha256') == SOURCE_HEADER_SHA, 'Unrecognized seed source')
    check(recipe['map']['size'] == MAP_SIZE and recipe['map']['sha256'] == MAP_SHA, 'Wrong pinned seed map')
    check(recipe['index']['archive']['size'] == ZIP_SIZE and recipe['index']['archive']['sha256'] == ZIP_SHA,
          'Wrong pinned seed ZIP')
    check(sum(p['size'] for p in recipe['index']['parts']) == ZIP_SIZE, 'Invalid seed part sizes')
    for name in required - {'recipe.json'}:
        spec = recipe['frames'][name]
        check((destination/name).stat().st_size == spec['size'] and digest_file(destination/name) == spec['sha256'],
              f'Seed frame {name} checksum failed')
    return recipe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    seed = sub.add_parser('make-seed')
    seed.add_argument('--map', required=True)
    seed.add_argument('--zip', required=True)
    seed.add_argument('--index', required=True)
    seed.add_argument('--output', required=True)
    rebuild = sub.add_parser('reconstruct')
    rebuild.add_argument('--seed', required=True)
    rebuild.add_argument('--seed-sha256', required=True)
    rebuild.add_argument('--output', required=True)
    rebuild.add_argument('--workers', type=int, default=4)
    verify = sub.add_parser('verify-local-framing')
    verify.add_argument('--seed-directory', required=True)
    verify.add_argument('--map', required=True)
    args = parser.parse_args()
    if args.action == 'make-seed':
        make_seed(args.map, args.zip, args.index, args.output)
    elif args.action == 'verify-local-framing':
        root = Path(args.seed_directory)
        recipe = json.loads((root/'recipe.json').read_text())
        check(digest_file(args.map) == MAP_SHA, 'Local PMTiles checksum failed')
        result = assemble_parts([root/'zip-prefix.bin', Path(args.map), root/'zip-suffix.bin'],
                                recipe['index'], root/'verification-only', write=False)
        log(f'Local exact ZIP and four chunk hashes passed: {result}')
    else:
        check(1 <= args.workers <= 8, 'Workers must be between 1 and 8')
        check(digest_file(args.seed) == args.seed_sha256, 'Downloaded seed SHA-256 failed')
        output = Path(args.output)
        recipe = unpack_seed(args.seed, output/'seed')
        map_path = output/'gb-basemap.pmtiles'
        reconstruct_map(output/'seed/map-prefix.bin', map_path, RangeFetcher(cache=output/'directories'), args.workers)
        assemble_parts([output/'seed/zip-prefix.bin', map_path, output/'seed/zip-suffix.bin'], recipe['index'], output/'parts')
        (output/'verified.json').write_text(json.dumps({'mapSha256': MAP_SHA, 'zipSha256': ZIP_SHA,
                                                       'parts': recipe['index']['parts']}, indent=2)+'\n')
        log('SUCCESS: exact map, exact ZIP, and all four exact part hashes verified')


if __name__ == '__main__':
    main()
