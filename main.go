package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)
func Encrypt(additionalData []byte) {
	var file string
	files, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if strings.Contains(f.Name(), "input") {
			file = f.Name()
		}
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	key, err := ioutil.ReadFile("k.txt")
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	ivdst := make([]byte, hex.EncodedLen(len(iv)))
	hex.Encode(ivdst, iv)
	//ioutil.WriteFile("iv.txt", dst, 0777)
	ciphertext := aesgcm.Seal(nil, iv, data, additionalData)
	dst := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(dst, ciphertext)
	extension := filepath.Ext(file)
	filename := file[0:len(file)-len(extension)]
	output := fmt.Sprintf("%s_%s", filename, extension)
	complete := append(ivdst, dst...)
	ioutil.WriteFile(output, complete, 0777)
}
func Decrypt(additionalData []byte) {
	var file string
	files, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if strings.Contains(f.Name(), "_") {
			file = f.Name()
		}
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, hex.DecodedLen(len(data)))
	hex.Decode(dst, data)
	iv := dst[:12]
	ciphertext := dst[12:]
	key, err := ioutil.ReadFile("k.txt")
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	//plain, err := aesgcm.Open(nil, iv, dst, additionalData)
	plain, err := aesgcm.Open(nil, iv, ciphertext, additionalData)
	if err != nil {
		panic(err)
	}
	extension := filepath.Ext(file)
	output := fmt.Sprintf("input%s", extension)
	ioutil.WriteFile(output, plain, 0777)
}
func main() {
	fmt.Println("1 encr 2 decr")
	buf := bufio.NewReader(os.Stdin)
	t, err := buf.ReadBytes('\n')
	if err != nil {
		panic(err)
	}
	ff := bytes.TrimSpace(t)
	additionalData := "Not Secret AAD Value"
	switch string(ff) {
	case "1":
		//iv := make([]byte, 12)
		//if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		//	panic(err)
		//}
		//dst := make([]byte, hex.EncodedLen(len(iv)))
		//hex.Encode(dst, iv)
		//ioutil.WriteFile("iv.txt", dst, 0777)
		Encrypt([]byte(additionalData))
	case "2":
		//iv, err := ioutil.ReadFile("iv.txt")
		//if err != nil {
		//	panic(err)
		//}
		//dst := make([]byte, hex.DecodedLen(len(iv)))
		//hex.Decode(dst, iv)
		Decrypt([]byte(additionalData))
	default:
	}
}
