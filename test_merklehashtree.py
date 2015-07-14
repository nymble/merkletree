#!/usr/bin/env python
""" test_merklehashtree.py

    Unit test for merklehashtree.py
    Prints output of all audit paths for a tree with 99 entries
    
    test_merklehashtree.py (c) by Paul A. Lambert

    test_merklehashtree.py is licensed under a
    Creative Commons Attribution 4.0 International License.

    You should have received a copy of the license along with this
    work. If not, see <http://creativecommons.org/licenses/by/4.0/>. 
"""
from merklehashtree import MerkleHashTree
import unittest

class TestMerkleTree(unittest.TestCase):
    """ """  
    def test_mht(self):
        """ Create and validate all paths for all trees up to size 99 """
        mht = MerkleHashTree()
        for i in range(0, 99):
            mht.addLeaf( 'this is leaf {}'.format(i) )
            n = len(mht) # should just be i+1
            
            # check audit path for every entry
            for m in range( n ):
                leaf = mht.leafHash(m)
                path = mht.auditPath(m)
                root = mht.rootHash()
                
                # validate path
                isValid = mht.validPath(m, n, leaf, root, path)
                self.assertTrue( isValid )

                # gratitous display of the audit path
                path_list = ''.join(['\n    - {}'.format( h.encode('hex')) for h in path])
                print audit_proof.format(m, n, leaf.encode('hex'), path_list, root.encode('hex'))

audit_proof = """--- audit proof
m:    {}
n:    {}
leaf: {}
path: {}
root: {}"""

if __name__ == "__main__":
    unittest.main()
