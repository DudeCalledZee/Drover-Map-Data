import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('reconstruction', Path(__file__).with_name('reconstruct-map-pack.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ReconstructionTest(unittest.TestCase):
    def test_run_mapping_preserves_shared_source_content(self):
        source = [(10, 4, 7, 90), (14, 1, 3, 120)]
        target = [(11, 1, 7, 0), (13, 1, 7, 7), (14, 1, 3, 14)]
        self.assertEqual([(90, 0, 7), (90, 7, 7), (120, 14, 3)], module.match_entries(source, target))

    def test_uncovered_tile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absent'):
            module.match_entries([(10, 2, 7, 90)], [(12, 1, 7, 0)])

    def test_changed_source_content_length_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'length changed'):
            module.match_entries([(10, 2, 8, 90)], [(11, 1, 7, 0)])

    def test_grouping_keeps_duplicate_destinations_and_exact_offsets(self):
        groups = module.group_ranges([(12, 20, 3), (10, 0, 4), (10, 4, 4), (100, 23, 2)], maximum=8, gap=0)
        self.assertEqual([(10, 5, [(0, 0, 4), (0, 4, 4), (2, 20, 3)]), (100, 2, [(0, 23, 2)])], groups)

    def test_group_size_remains_bounded(self):
        groups = module.group_ranges([(0, 0, 4), (4, 4, 4), (8, 8, 4)], maximum=8, gap=0)
        self.assertEqual([8, 4], [g[1] for g in groups])

    def make_parts_fixture(self, root):
        paths=[]
        for number, data in enumerate((b'ab', b'cdefg', b'hi')):
            path=root/str(number)
            path.write_bytes(data)
            paths.append(path)
        parts=[{'name':'part1','size':4,'sha256':hashlib.sha256(b'abcd').hexdigest()},
               {'name':'part2','size':5,'sha256':hashlib.sha256(b'efghi').hexdigest()}]
        return paths, {'parts':parts,'archive':{'size':9,'sha256':hashlib.sha256(b'abcdefghi').hexdigest()}}

    def test_framing_crosses_multiple_file_and_part_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            paths,index=self.make_parts_fixture(root)
            module.assemble_parts(paths,index,root/'parts')
            self.assertEqual(b'abcd',(root/'parts/part1').read_bytes())
            self.assertEqual(b'efghi',(root/'parts/part2').read_bytes())

    def test_corrupt_part_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            paths,index=self.make_parts_fixture(root)
            index['parts'][1]['sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'SHA-256 failed'):
                module.assemble_parts(paths,index,root/'parts')
            self.assertEqual([],list((root/'parts').iterdir()))

    def test_truncated_framing_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            paths,index=self.make_parts_fixture(root)
            with self.assertRaisesRegex(ValueError,'Truncated'):
                module.assemble_parts(paths[:-1],index,root/'parts',write=False)

if __name__ == '__main__':
    unittest.main()
