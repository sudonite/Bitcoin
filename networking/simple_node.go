package networking

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	bloomfilter "github.com/sudonite/bitcoin/bloom_filter"
	merkletree "github.com/sudonite/bitcoin/merkle_tree"
)

// Message interface defines the methods any Bitcoin network message must implement.
type Message interface {
	Command() string
	Serialize() []byte
}

// Message interface defines the methods any Bitcoin network message must implement.
type SimpleNode struct {
	host        string
	port        uint16
	testnet     bool
	receiveMsgs []Message
}

// NewSimpleNode creates a new SimpleNode instance for a given host, port, and testnet flag.
func NewSimpleNode(host string, port uint16, testnet bool) *SimpleNode {
	return &SimpleNode{
		host:    host,
		port:    port,
		testnet: testnet,
	}
}

// Run connects to the peer and performs the handshake, then requests headers.
func (s *SimpleNode) Run() {
	conStr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))
	conn, err := net.Dial("tcp", conStr)
	if err != nil {
		panic(err)
	}

	s.WaitFor(conn)
	s.GetHeaders(conn)
}

func (s *SimpleNode) GetData(conn net.Conn) {
	// prepare bloom filter
	txHash, err := hex.DecodeString("1df77b894e1910628714bb73df59e20fb9114f9dcc051d8c03ca197dd112cc8a")
	if err != nil {
		panic(err)
	}
	bf := bloomfilter.NewBloomFilter(30, 5, 90210)
	// set up bloomfilter ask full node to return any transaction of whichs id
	// map to buckets that have all value 1
	bf.Add(txHash)
	// send filterload
	s.Send(conn, bf.FilterLoadMsg())
	getdata := bloomfilter.NewGetDataMessage()
	receiveMerkleBlock := false

	blockHash, _ := hex.DecodeString("0000000000000138f016a6fc1666fd667b7d282d65ad14b7f0b16a75a2e90e50")
	getdata.AddData(bloomfilter.FilteredDataType(), blockHash)
	s.Send(conn, getdata)

	for !receiveMerkleBlock {
		// let the peer have a rest
		time.Sleep(2 * time.Second)
		msgs := s.Read(conn)
		for i := 0; i < len(msgs); i++ {
			msg := msgs[i]
			fmt.Printf("receiving command: %s\n", msg.command)
			command := string(bytes.Trim(msg.command, "\x00"))

			if command == "merkleblock" {
				merkleBlock := merkletree.ParseMerkleBlock(msg.payload)
				fmt.Printf("merkleblock received: %s\n", merkleBlock)
				fmt.Printf("merkleblock valid:%v\n", merkleBlock.IsValid())
				receiveMerkleBlock = true
			}

		}
	}
}

// GetHeaders sends a "getheaders" message and waits for "headers" response from the peer.
func (s *SimpleNode) GetHeaders(conn net.Conn) {
	// after handshaking we send get header request
	getHeadersMsg := NewGetHeaderMessage(GetGenesisBlockHash())
	fmt.Printf("get header raw:%x\n", getHeadersMsg.Serialize())

	s.Send(conn, getHeadersMsg)
	receivedGetHeader := false
	for !receivedGetHeader {
		// let the peer have a rest
		time.Sleep(2 * time.Second)
		msgs := s.Read(conn)
		for i := 0; i < len(msgs); i++ {
			msg := msgs[i]
			fmt.Printf("receiving command: %s\n", msg.command)
			command := string(bytes.Trim(msg.command, "\x00"))
			if command == "headers" {
				receivedGetHeader = true
				blocks := ParseGetHeader(msg.payload)
				for i := 0; i < len(blocks); i++ {
					fmt.Printf("block header:\n%s\n", blocks[i])
				}
			}
		}
	}
}

// Send serializes a Message into a NetworkEnvelope and writes it to the TCP connection.
func (s *SimpleNode) Send(conn net.Conn, msg Message) {
	envelop := NewNetworkEnvelope([]byte(msg.Command()), msg.Serialize(), s.testnet)
	n, err := conn.Write(envelop.Serialize())
	if err != nil {
		panic(err)
	}

	fmt.Printf("write to %d bytes\n", n)
}

// Read reads all available data from the TCP connection and returns parsed NetworkEnvelopes.
func (s *SimpleNode) Read(conn net.Conn) []*NetworkEnvelope {
	receivedBuf := make([]byte, 0)
	totalLen := 0
	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}
		totalLen += n
		receivedBuf = append(receivedBuf, buf...)
		if n < 4096 {
			break
		}
	}

	var msgs []*NetworkEnvelope
	parsedLen := 0
	for {
		if parsedLen >= totalLen {
			break
		}
		msg := ParseNetwork(receivedBuf, s.testnet)
		msgs = append(msgs, msg)

		if parsedLen < totalLen {
			parsedLen += len(msg.Serialize())
			receivedBuf = receivedBuf[len(msg.Serialize()):]
		}
	}
	return msgs
}

// WaitFor performs the version handshake with a peer
func (s *SimpleNode) WaitFor(conn net.Conn) {
	s.Send(conn, NewVersionMessage())

	verackReceived := false
	versionReceived := false
	for !verackReceived || !versionReceived {
		msgs := s.Read(conn)
		for i := 0; i < len(msgs); i++ {
			msg := msgs[i]
			command := string(bytes.Trim(msg.command, "\x00"))
			fmt.Printf("command:%s\n", command)
			if command == "verack" {
				fmt.Printf("receiving verack message from peer\n")
				verackReceived = true
			}
			if command == "version" {
				versionReceived = true
				fmt.Printf("receiving version message from peer\n: %s", msg)
				s.Send(conn, NewVerAckMessage())

			}

		}

	}
}
