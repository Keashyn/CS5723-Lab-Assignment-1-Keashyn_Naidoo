package main

import (
	"fmt"
	"strconv"
)

func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	msgString := "forge by keashyn.naidoo@my.utsa.edu"

	var sig Signature
	// your code here!
	// ==
	//Initialize the secret key to find
	var sec SecretKey
	//
	var array [256][2]int
	for k := 0; k < len(sigslice); k++ {
		fmt.Println(k)

		var hashedSig Signature
		//Get the signature from sigslice array
		sig = sigslice[k]
		//Hash the signature so that I can compare it with the public key
		for i := 0; i < 256; i++ {
			hashedSig.Preimage[i] = sig.Preimage[i].Hash()
		}
		//Compare this hash and public key OneHash

		for i := 0; i < 256; i++ {
			oneC, zeroC := 0, 0
			if hashedSig.Preimage[i] == pub.OneHash[i] {
				sec.OnePre[i] = sig.Preimage[i]
				oneC = 1
			}
			if hashedSig.Preimage[i] == pub.ZeroHash[i] {
				sec.ZeroPre[i] = sig.Preimage[i]
				zeroC = 1

			}
			if array[i][0] > 0 {

			} else {
				array[i][0] += zeroC
			}
			if array[i][1] > 0 {

			} else {
				array[i][1] += oneC
			}

		}

	}
	var dummy string
	fmt.Println(array)
	fmt.Println("Len array is ", len(array))
	fmt.Println("Continue?: ")
	fmt.Scanln(&dummy)
	counter := 0
	c := 0
	for c != 256 {

		counter += 1
		msgString = "forged by keashyn.naidoo@my.utsa.edu" + strconv.Itoa(counter)
		msg := GetMessageFromString(msgString)

		if counter%10000000 == 0 {
			fmt.Println(msgString)
			fmt.Println(c)
		}
		c = 0
	out:
		for i := 0; i < 32; i++ {
			for j := 0; j < 8; j++ {
				index := 8*i + j
				if int(msg[i])&(1<<j) == 0 {
					if array[index][0] == 0 {
						break out
					} else {
						c++
					}
				} else if int(msg[i])&(1<<j) == 1 {
					if array[index][1] == 0 {
						break out
					} else {
						c++
					}
				}
			}
		}

	}

	return msgString, sig, nil

}
