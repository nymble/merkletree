# A Python implementation and test code of the Merkle Hash Tree Algorithm

This Merkle Hash Tree Implementation is roughly aligned to the notation and
hash method of: https://tools.ietf.org/html/draft-laurie-pki-sunlight-02 
       
## Merkle Hash Tree Examples and Algorithms 
                                                0,5
                                               __|__
                                              /     \
           0,3            0,4               0,4     4,5   
          __|__          __|__             __|__     |
         /     \        /     \           /     \   d4
       0,2     2,3    0,2     2,4       0,2     2,4
      /   \     |     / \     / \       / \     / \
    0,1   1,2  d2   0,1 1,2 2,3 3,4   0,1 1,2 2,3 3,4
     |     |         |   |   |   |     |   |   |   |
    d0    d1        d0  d1  d2  d3    d0  d1  d2  d3
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
        mth(0,i+1) = hash( 1 + mth(k1,k) + mth(k,k2))
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
