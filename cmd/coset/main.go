// Copyright (c) 2022, Fredrik Skogman

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.

// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS ORSERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/veraison/go-cose"
)

const (
	KeyEcdsa = "ecdsa"
)

func usage() {
	me := filepath.Base(os.Args[0])
	fmt.Printf("usage: %s [-g keytype] [-s] -m msg|-f file [-k file] [-e aad] [-t contet-type] [-o format]\n", me)
	os.Exit(1)
}

func main() {
	var err error
	g := flag.String("g", "", "Generate key pair")
	s := flag.Bool("s", false, "Sign content")
	k := flag.String("k", "", "Key to use")
	e := flag.String("e", "", "Extra AAD, base64 encoded")
	m := flag.String("m", "", "Message (string) to sign")
	f := flag.String("f", "", "File to content or CBOR data")
	t := flag.String("t", "", "Content type of the message")
	o := flag.String("o", "", "Output payload in text, hex or base64 format")

	flag.Parse()

	if *g != "" {
		gpk, err := generateKey(*g)
		if err != nil {
			panic(err)
		}
		pk := gpk.(*ecdsa.PrivateKey)
		storePrivateKey(pk)
		storePublicKey(pk.Public())
		return
	}

	if !*s && *k == "" {
		// key must be provided for verification
		fmt.Println("No key provided")
		usage()
	}
	if *m == "" && *f == "" {
		// No content provided
		fmt.Println("No content provided")
		usage()
	}

	if *m != "" && *f != "" {
		// Message and file provded
		fmt.Println("Both message and file provided")
		usage()
	}

	// Prepare content
	var c []byte
	if *m != "" {
		c = []byte(*m)
	} else {
		file, err := os.Open(*f)
		defer file.Close()
		c, err = io.ReadAll(file)
		if err != nil {
			panic(err)
		}
	}
	// Unpack AAD/external
	var eaad []byte
	if *e != "" {
		eaad, err = base64.StdEncoding.DecodeString(*e)
		if err != nil {
			fmt.Println("Failed to extract extra AAD")
			panic(err)
		}
	}

	if *s {
		var pk *ecdsa.PrivateKey

		if *k == "" {
			gpk, err := generateKey(KeyEcdsa)
			if err != nil {
				fmt.Println("Could not generate key")
				panic(err)
			}
			pk = gpk.(*ecdsa.PrivateKey)
		} else {
			// read key file
			pk, err = loadPrivateKey(*k)
			if err != nil {
				panic(err)
			}
		}

		sign(pk, c, eaad, *t)
		if *k == "" {
			storePublicKey(pk.Public())
		}
	} else {
		pk, err := loadPublicKey(*k)
		msg, err := verify(pk, c, eaad)

		if err != nil {
			panic(err)
		}

		var str string
		switch *o {
		case "text":
			str = string(msg.Payload)
		case "hex":
			str = hex.EncodeToString(msg.Payload)
		case "base64":
			str = base64.StdEncoding.EncodeToString(msg.Payload)
		default:
			str = fmt.Sprintf("Output format '%s' not supported", *o)
		}
		fmt.Println(str)
	}
}

func sign(pk *ecdsa.PrivateKey, c, eaad []byte, ctype string) {
	protected := cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
	}
	if ctype != "" {
		protected[cose.HeaderLabelContentType] = ctype
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, pk)
	msg, err := cose.Sign1(rand.Reader, signer, protected, c, eaad)
	sig, err := msg.MarshalCBOR()
	if err != nil {
		fmt.Println("Failed to marshal signature into CBOR")
		panic(err)
	}
	file, err := os.Create("sig.cbor")
	if err != nil {
		fmt.Println("Could not open file for writing")
		panic(err)
	}
	defer file.Close()
	n, err := file.Write(sig)
	if err != nil {
		panic(err)
	}
	if n != len(sig) {
		panic("Not all data written")
	}
}

func verify(pk crypto.PublicKey, c, eaad []byte) (*cose.Sign1Message, error) {
	var msg cose.Sign1Message

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pk)
	if err != nil {
		return nil, err
	}
	err = msg.UnmarshalCBOR(c)
	if err != nil {
		return nil, err
	}
	err = msg.Verify(eaad, verifier)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}

func generateKey(typ string) (crypto.PrivateKey, error) {
	switch typ {
	case KeyEcdsa:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	return nil, errors.New("unsupported key type")
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Could not open key file")
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Failed to read key")
		return nil, err
	}
	block, rest := pem.Decode(b)
	if len(rest) > 0 {
		fmt.Printf("%d bytes trailing in key file", len(rest))
	}

	switch block.Type {
	case "EC PRIVATE KEY":
	default:
		return nil, errors.New("Invalid key type")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func loadPublicKey(path string) (crypto.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Could not open key file")
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Failed to read key")
		return nil, err
	}
	block, rest := pem.Decode(b)
	if len(rest) > 0 {
		fmt.Printf("%d bytes trailing in key file", len(rest))
	}

	switch block.Type {
	case "PUBLIC KEY":
	default:
		return nil, errors.New("Invalid key type")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}

func storePrivateKey(pk *ecdsa.PrivateKey) {
	var err error
	block := pem.Block{
		Type: "EC PRIVATE KEY",
	}
	block.Bytes, err = x509.MarshalECPrivateKey(pk)
	if err != nil {
		panic(err)
	}
	fKey, err := os.Create("private.pem")
	if err != nil {
		fmt.Println("Could not open file for writing")
		panic(err)
	}
	defer fKey.Close()
	err = pem.Encode(fKey, &block)
	if err != nil {
		fmt.Println("Failed to write public key")
	}
}

func storePublicKey(pk crypto.PublicKey) {
	var err error
	block := pem.Block{
		Type: "PUBLIC KEY",
	}
	block.Bytes, err = x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		panic(err)
	}
	fKey, err := os.Create("public.pem")
	if err != nil {
		fmt.Println("Could not open file for writing")
		panic(err)
	}
	defer fKey.Close()
	err = pem.Encode(fKey, &block)
	if err != nil {
		fmt.Println("Failed to write public key")
	}
}
