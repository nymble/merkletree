#!/usr/bin/env python
""" merklehashtree.py
   
    This Merkle Hash Tree Implementation is roughly aligned to the notation and
    hash method of: draft-laurie-pki-sunlight-02.txt 
       
    Merkle Hash Tree Examples and Algorithms 
    
           0,3              0,4        
          __|__            __|__ 
         /     \          /     \
       0,2     2,3      0,2     2,4
      /   \     |       / \     / \
    0,1   1,2  d2     0,1 1,2 2,3 3,4
     |     |           |   |   |   |
    d0    d1          d0  d1  d2  d3

   Each node in the tree can be identified as a tuple representing the range
   of values covered by the hash.
   
   For a Merkle Hash Tree with n leaf nodes and each i,j node
   identified by mth(i,j):
    - the root hash, MTH = mth(0,n)
    - the leaf hash for data entry di with 0<=i<n is mth(i,i+1)
    - leaf values are formed by hashing the input string d(i)
        mth(i,i+1) = hash( 0 | d(i))
        This is a hash of the single octet with value 0 concatenated with
        the ith input string d(i)
    - every non-leaf node mth(k1,k2) has the property that
        mth(k1,k2) = hash( 1 | mth(k1,k1+k) | mth(k1+k,k2) )
        where k = k1+lp2(k2-k1) , and lp2 is the largest power of 2 < (k2-k1)
    - new entries are added to the tree by:
      creating a leaf node
        mth(i,i+1) = hash( 0 | d(i))
    - root hash is calculated when needed by:
        mth(0,i+1) = hash( 1 + smth(k1,k) + self.mth(k,k2))
        and recursively creating any mth(i,j) needed for the new root hash
    - an empty tree has a root hash value formed by hashing
      a null string, hash('')
      

                  0,7
             ______|______
            /             \   
          0,4             4,7           
         __|__           __|__
        /     \         /     \
      0,2     2,4     4,6     6,7
      / \     / \     / \      |
    0,1 1,2 2,3 3,4 4,5 5,6   d6
     |   |   |   |   |   |
    d0  d1  d2  d3  d4  d5  

   
   The audit path for d0 is [mth(1,2), mth(2,4), mth(4,7)]
   The audit path for d3 is [mth(2,3), mth(0,2), mth(4,7)]
   The audit path for d4 is [mth(5,6), mth(6,7), mth(0,4)]
   The audit path for d6 is [mth(4,6), mth(0,4)]

   merklehashtree.py (c) by Paul A. Lambert

   merklehashtree.py is licensed under a
   Creative Commons Attribution 4.0 International License.

   You should have received a copy of the license along with this
   work. If not, see <http://creativecommons.org/licenses/by/4.0/>. 
   
   2012-12-12 First Version
"""
from hashlib import sha256 # Default hash algorithm

class MerkleHashTree():
    """  Merkle Hash Tree """
    
    def addLeaf(self, string):
        """ Create a new leaf node for the string 'd' """
        hashValue = self.hash(chr(0) + string)
        self.size += 1
        self._storeNode(self.size-1, self.size, hashValue)

    def mth(self, k1, k2):
        """ Merkle Tree Hash funcion recursively creates required nodes"""
        try:
            mNode = self._retrieveNode(k1, k2)
        except KeyError, v:   # no stored node, so make one
            k = k1 + largestPower2(k2-k1)
            mNode = self.hash(chr(1) + self.mth(k1, k) + self.mth(k,k2))
            self._storeNode(k1, k2, mNode)
        return mNode

    def auditPath(self, m, n=None):
        """ return a list of hash values for entry d(m) that proves
            that d(m) is contained in the nth root hash with 0 <= m < n
        """
        if not n: n = self.size
        def _auditPath(m, k1, k2):
            """ Recursively collect audit path """
            if (k2-k1) == 1:
                return [ ] # terminate with null list when range is a single node
            k = k1 + largestPower2(k2-k1)
            if m < k:
                path = _auditPath(m, k1, k) + [self.mth(k,k2),]
            else:
                path = _auditPath(m, k, k2) + [self.mth(k1,k),]
            return path
        
        return _auditPath(m, 0, n)

    def validPath(self, m, n, leaf_hash, root_hash, audit_path):
        """ Test if leaf_hash is contained under a root_hash
            as demonstrated by the audit_path """
        
        def _hashAuditPath(m, k1, k2, i):
            """ Recursively calculate hash value """
            if len(audit_path) == i:
                return leaf_hash
            k = k1 + largestPower2(k2-k1)
            ithAuditNode = audit_path[len(audit_path) - 1 - i]
            if m < k:
                hv = self.hash(chr(1) + _hashAuditPath(m, k1, k, i+1) + ithAuditNode )
            else:
                hv = self.hash(chr(1) + ithAuditNode + _hashAuditPath(m, k, k2, i+1) )
            return hv
           
        hv = _hashAuditPath(m, 0, n, 0)        
        return hv == root_hash
    
    def rootHash(self, n=None):
        """ Root hash of tree for nth root """
        if not n: n = self.size
        if n > 0:
            return self.mth(0, n)
        else:
            return self.hash('')  # empty tree is hash of null string
            
    def leafHash(self, m):
        """ Leaf hash value for mth entry """
        return self.mth(m, m+1)
            
    def hash(self, input):
        """ Wrapper for hash functions """
        return self._hashalg(input).digest()
     
    def __init__(self, HashAlg = sha256):
        self._hashalg = HashAlg
        self.size = 0 # number of leaf nodes in tree
        self._inittree()   # create empty mht
        
    def __len__(self):
        return self.size

    # Overload the following for persistant trees
    def _inittree(self):
        self.hashtree = {} 
        
    def _retrieveNode(self, k1, k2):
        return self.hashtree[(k1,k2)]
    
    def _storeNode(self, k1, k2, mNode):
        # leaf and non-leaf nodes in the same dictionary indexed by range tuple
        assert k1 < k2 <= self.size
        self.hashtree[(k1,k2)] = mNode
        
def largestPower2(n):
    """ Return the largest power of 2 less than n """
    lp2 = 1
    while lp2 < n :
        lp2 = lp2 << 1
    return lp2 >> 1
