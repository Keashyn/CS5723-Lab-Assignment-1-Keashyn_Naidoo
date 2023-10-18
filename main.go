// Problem set 01: Hash based signatures.
// In this pset1, I need to build a hash based signature system.  I'll use sha256
// as our hash function, and Lamport's simple signature design.

// If you run `go test` and everything passes, you're all set.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {

	// Define your message
	textString := "good"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%b\n", m[:])

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("zeropre\n\n")
	fmt.Println(sec.ZeroPre)
	fmt.Printf("onepre\n\n")
	fmt.Println(sec.OnePre)
	// sign message
	sig1 := Sign(m, sec)
	fmt.Printf("sigpre\n\n")
	fmt.Println(sig1)

	fmt.Println(sec.OnePre[2].IsPreimage(pub.OneHash[2]))
	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	/*
		// Forge signature
		msgString, sig, err := Forge()
		if err != nil {
			panic(err)
		}

		fmt.Printf("forged msg: %s sig: %s\n", msgString, sig.ToHex())
	*/
	return
}

// Signature systems have 3 functions: GenerateKey(), Sign(), and Verify().
// We'll also define the data types: SecretKey, PublicKey, Message, Signature.

// --- Types

// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte

type SecretKey struct {
	ZeroPre [256]Block
	OnePre  [256]Block
}

type PublicKey struct {
	ZeroHash [256]Block
	OneHash  [256]Block
}

// --- Methods on PublicKey type

// ToHex gives a hex string for a PublicKey. no newline at the end
func (self PublicKey) ToHex() string {
	// format is zerohash 0...255, onehash 0...255
	var s string
	for _, zero := range self.ZeroHash {
		s += zero.ToHex()
	}
	for _, one := range self.OneHash {
		s += one.ToHex()
	}
	return s
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// A message to be signed is just a block.
type Message Block

// --- Methods on the Block type

// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// Y = hash(X), then X.IsPreimage(Y) will return true,

func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

// A signature consists of 32 blocks.  It's a selective reveal of the private
// key, according to the bits of the message.
type Signature struct {
	Preimage [256]Block
}

// ToHex returns a hex string of a signature
func (self Signature) ToHex() string {
	var s string
	for _, b := range self.Preimage {
		s += b.ToHex()
	}

	return s
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey
	var err error

	for i := range sec.ZeroPre {

		// SEE: https://pkg.go.dev/crypto/rand

		_, err = rand.Read(sec.ZeroPre[i][:]) // [:] transfor array in slice to pass as a argument in rand
		_, err = rand.Read(sec.OnePre[i][:])
		if err != nil {
			fmt.Println("error:", err)
			break
		}
		pub.ZeroHash[i] = (BlockFromByteSlice(sec.ZeroPre[i][:])).Hash()
		pub.OneHash[i] = (BlockFromByteSlice(sec.OnePre[i][:])).Hash()
	}

	return sec, pub, err
}

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature
	for i := range msg {
		for j := 7; j >= 0; j-- {
			k := i*8 + (7 - j) // calculate index for signature: i'th byte * 8 + (7-j) bit
			if msg[i]&(1<<j) != 0 {
				sig.Preimage[k] = sec.OnePre[k]
			} else {
				sig.Preimage[k] = sec.ZeroPre[k]
			}
		}
	}
	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {
	b := true
	for i := range msg {
		for j := 7; j >= 0; j-- {
			k := i*8 + (7 - j) // calculate index
			if msg[i]&(1<<j) != 0 {
				if !sig.Preimage[k].IsPreimage(pub.OneHash[k]) {
					b = false
				}
			} else {
				if !sig.Preimage[k].IsPreimage(pub.ZeroHash[k]) {
					b = false
				}
			}
		}
	}
	return b
}
