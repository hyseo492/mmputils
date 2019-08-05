package mmputils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
)

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	checkError(err)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func getUserHomeDirectoryPath() string {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("No Search Home Directory")
		return ""
	}
	return homeDirectory
}

func makeCertificationFile() string {
	homeDirectory := getUserHomeDirectoryPath()
	if homeDirectory == "" {
		fmt.Println("Error Find User Home Directory")
		return ""
	}

	keyFilePath := filepath.Join(getUserHomeDirectoryPath(), ".meshId")
	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		os.Mkdir(keyFilePath, os.ModePerm)
	}

	if !exists(filepath.Join(keyFilePath, "private.key")) || !exists(filepath.Join(keyFilePath, "public.key")) {
		fmt.Println("Create New Key File")
		reader := rand.Reader
		bitSize := 2048

		key, err := rsa.GenerateKey(reader, bitSize)
		checkError(err)

		publicKey := key.PublicKey

		saveGobKey(filepath.Join(keyFilePath, "private.key"), key)
		savePEMKey(filepath.Join(keyFilePath, "private.pem"), key)

		saveGobKey(filepath.Join(keyFilePath, "public.key"), publicKey)
		savePublicPEMKey(filepath.Join(keyFilePath, "public.pem"), publicKey)

		hash := md5.New()
		asn1Bytes, err := asn1.Marshal(publicKey)
		hash.Write(asn1Bytes)

		meshId := hex.EncodeToString(hash.Sum(nil))
		fmt.Println("Mesh ID = " + meshId)

		return meshId
	}

	return ""
}

func GetMeshId() string {
	keyFilePath := filepath.Join(getUserHomeDirectoryPath(), ".meshId")
	if !exists(filepath.Join(keyFilePath, "private.key")) || !exists(filepath.Join(keyFilePath, "public.key")) {
		meshId := makeCertificationFile()
		return meshId
	} else {
		fmt.Println("Key File Exist")
		publicPem, err := ioutil.ReadFile(filepath.Join(keyFilePath, "public.pem"))
		if err != nil {
			fmt.Println("public.pem File Read Error")
			return ""
		}
		block, _ := pem.Decode(publicPem)

		hash := md5.New()
		hash.Write(block.Bytes)
		meshId := hex.EncodeToString(hash.Sum(nil))
		fmt.Println("Mesh ID = " + meshId)
		return meshId
	}
}