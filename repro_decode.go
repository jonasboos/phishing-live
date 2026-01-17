package main

import (
	"fmt"
	"mime"
)

func main() {
	// The string from the user
	input := "=?UTF-8?Q?\"WIBTAH_for_banning_my_aunt=E2=80=99s_friend_an?= =?UTF-8?Q?d_her_daughter_from_my_home_after_th...\"?="

	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(input)
	if err != nil {
		fmt.Printf("Error decoding: %v\n", err)
	}
	fmt.Printf("Input: %s\n", input)
	fmt.Printf("Decoded: %s\n", decoded)

	// Test with quotes inside
	input2 := "=?UTF-8?Q?\"quoted\"?="
	decoded2, err2 := dec.DecodeHeader(input2)
	fmt.Printf("Input2: %s\nDecoded2: %s\nError2: %v\n", input2, decoded2, err2)
}
