package merkletree

import (
	"fmt"
	"math"
	"strings"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

// MerkleParent calculates the parent hash of two child hashes by concatenating and double SHA256 hashing them.
func MerkleParent(hash1 []byte, hash2 []byte) []byte {
	buf := make([]byte, 0)
	buf = append(buf, hash1...)
	buf = append(buf, hash2...)
	return ecc.Hash256(string(buf))
}

// MerkleParent calculates the parent hash of two child hashes by concatenating and double SHA256 hashing them.
func MerkleParentLevel(hashes [][]byte) [][]byte {
	if len(hashes) == 1 {
		panic("Can't take parent level with onl y 1 item")
	}

	if len(hashes)%2 == 1 {
		// odd number, dpulicate the last one
		hashes = append(hashes, hashes[len(hashes)-1])
	}

	parentLevel := make([][]byte, 0)
	for i := 0; i < len(hashes); i += 2 {
		parent := MerkleParent(hashes[i], hashes[i+1])
		parentLevel = append(parentLevel, parent)
	}

	return parentLevel
}

// MerkleRoot computes the Merkle root of a list of hashes.
func MerkleRoot(hashes [][]byte) []byte {
	curLevel := hashes
	for len(curLevel) > 1 {
		curLevel = MerkleParentLevel(curLevel)
	}

	return curLevel[0]
}

// ConstructTree creates a skeleton Merkle tree with the given number of leaves (nodes).
func ConstructTree(n int32) [][][]byte {
	maxDepth := math.Ceil(math.Log2(float64(n))) + 1
	merkleTree := make([][][]byte, int(maxDepth))
	nodesInLayer := int(n)
	for depth := maxDepth; depth > 0; depth-- {
		layer := make([][]byte, 0)

		for i := 0; i < nodesInLayer; i++ {
			layer = append(layer, []byte{})
		}

		merkleTree[int(depth-1)] = layer
		if nodesInLayer%2 == 0 {
			nodesInLayer = nodesInLayer / 2
		} else {
			nodesInLayer = (nodesInLayer + 1) / 2
		}
	}

	return merkleTree
}

// MerkleTree represents a full Merkle tree with pointer to current node for traversal.
type MerkleTree struct {
	total int
	nodes [][][]byte
	// combine currentDepth and currentIndex we point to a given node
	currentDepth int32
	currentIndex int32
	maxDepth     int32
}

// InitEmptyMerkleTree creates an empty Merkle tree with given number of leaves.
func InitEmptyMerkleTree(total int) *MerkleTree {
	merkleTree := &MerkleTree{
		total:        total,
		currentDepth: 0,
		currentIndex: 0,
		maxDepth:     int32(math.Ceil(math.Log2(float64(total)))),
	}
	merkleTree.nodes = ConstructTree(int32(total))

	return merkleTree
}

// NewMerkleTree constructs a full Merkle tree from a list of leaf hashes.
func NewMerkleTree(hashes [][]byte) *MerkleTree {
	merkleTree := &MerkleTree{
		total:        len(hashes),
		currentDepth: 0,
		currentIndex: 0,
		maxDepth:     int32(math.Ceil(math.Log2(float64(len(hashes))))),
	}

	merkleTree.nodes = ConstructTree(int32(merkleTree.total))
	// set up the lowest layer
	for idx, hash := range hashes {
		merkleTree.nodes[merkleTree.maxDepth][idx] = hash
	}
	// set up nodes in up layer
	for len(merkleTree.Root()) == 0 {
		if merkleTree.IsLeaf() {
			merkleTree.Up()
		} else {
			leftHash := merkleTree.GetLeftNode()
			rightHash := merkleTree.GetRightNode()
			if len(leftHash) == 0 {
				merkleTree.Left()
			} else if len(rightHash) == 0 {
				merkleTree.Right()
			} else {
				// both left and right childs are ready, set the current node
				merkleTree.SetCurrentNode(MerkleParent(leftHash, rightHash))
				merkleTree.Up()
			}
		}
	}
	return merkleTree
}

// String returns a readable representation of the Merkle tree.
func (m *MerkleTree) String() string {
	result := make([]string, 0)
	for depth, level := range m.nodes {
		items := make([]string, 0)
		for index, h := range level {
			short := "nil"
			if len(h) != 0 {
				// only print out first 8 digits of the hash value
				short = fmt.Sprintf("%x...", h[:4])
			}
			if depth == int(m.currentDepth) && index == int(m.currentIndex) {
				// current node is being pointed to,then we just show 6 digits with two *
				items = append(items, fmt.Sprintf("*%x*", h[:3]))
			} else {
				items = append(items, short)
			}
		}

		result = append(result, strings.Join(items, ","))
	}

	return strings.Join(result, "\n")
}

// PopulateTree fills a Merkle tree using flag bits and leaf hashes (used in partial Merkle trees).
func (m *MerkleTree) PopluateTree(flagBits string, hashes [][]byte) {
	for len(m.Root()) == 0 {
		if m.IsLeaf() {
			// for leaf we always has its value in hashes
			flagBits = flagBits[1:]
			// value for the node can get from hashes
			m.SetCurrentNode(hashes[0])
			// remove the hash value
			hashes = hashes[1:]
			m.Up()
		} else {
			leftHash := m.GetLeftNode()

			if len(leftHash) == 0 {
				if flagBits[0] == '0' {
					// we have current node's value in hashes
					m.SetCurrentNode(hashes[0])
					hashes = hashes[1:]
					// we don't need to visit its children any more
					m.Up()
				} else {
					m.Left()
				}
				//w e only remove current bit if we are first visit to the node
				flagBits = flagBits[1:]
			} else if m.RightExist() {
				rightHash := m.GetRightNode()
				if len(rightHash) == 0 {
					m.Right()
				} else {
					// both left and right child ready
					m.SetCurrentNode(MerkleParent(leftHash, rightHash))
					m.Up()
				}
			} else {
				// duplicate the left child
				m.SetCurrentNode(MerkleParent(leftHash, leftHash))
				m.Up()
			}
		}
	}

	if len(hashes) != 0 {
		panic("hahses not all consumed")
	}
	for _, bit := range flagBits {
		// if we still have bit value of 1, which means there are nodes left without handled
		if bit != '0' {
			panic("flag bits not all consumed")
		}
	}
}

// Up moves the current pointer to the parent node.
func (m *MerkleTree) Up() {
	// point to current node's parent
	if m.currentDepth > 0 {
		m.currentDepth -= 1
	}
	m.currentIndex /= 2
}

// Left moves the current pointer to the left child node.
func (m *MerkleTree) Left() {
	m.currentDepth += 1
	m.currentIndex *= 2
}

// Right moves the current pointer to the right child node.
func (m *MerkleTree) Right() {
	m.currentDepth += 1
	m.currentIndex = m.currentIndex*2 + 1
}

// Root returns the Merkle root of the tree.
func (m *MerkleTree) Root() []byte {
	return m.nodes[0][0]
}

// SetCurrentNode sets the value of the current node.
func (m *MerkleTree) SetCurrentNode(value []byte) {
	m.nodes[m.currentDepth][m.currentIndex] = value
}

// GetCurrentNode returns the value of the current node.
func (m *MerkleTree) GetCurrentNode() []byte {
	return m.nodes[m.currentDepth][m.currentIndex]
}

// GetLeftNode returns the left child of the current node.
func (m *MerkleTree) GetLeftNode() []byte {
	return m.nodes[m.currentDepth+1][m.currentIndex*2]
}

// GetRightNode returns the right child of the current node.
func (m *MerkleTree) GetRightNode() []byte {
	return m.nodes[m.currentDepth+1][m.currentIndex*2+1]
}

// IsLeaf checks if the current node is a leaf.
func (m *MerkleTree) IsLeaf() bool {
	return m.currentDepth == m.maxDepth
}

// RightExist checks if the right child exists for the current node.
func (m *MerkleTree) RightExist() bool {
	return len(m.nodes[m.currentDepth+1]) > int(m.currentIndex)*2+1
}
