package gocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

// Generates a base64 encoded 32 Byte secret key for AES 256 encryption and writes it to a file.
func GenerateSecret(passphrase string, output_file string) {

	salt := make([]byte, 32)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		log.Fatal("Salt could not be generated.")
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)

	if err != nil {
		log.Fatal("Key could not be derived.")
	}

	enc_str := base64.StdEncoding.EncodeToString(dk)

	file_err := os.WriteFile(output_file, []byte(enc_str), 0644)

	if file_err != nil {
		log.Fatal("Error writing key to file.")
	}
}

func ReadSecret(input_file string) []byte {
	secret_key, err := os.ReadFile(input_file)

	if err != nil {
		log.Fatal(fmt.Sprintf("Error reading key from %v.", input_file))
	}

	bytes, err := base64.StdEncoding.DecodeString(string(secret_key))
	if err != nil {
		log.Fatal(fmt.Sprintf("Error decoding key from %v.", input_file))
	}

	return bytes
}

// Encrypts a given file...
func Encrypt(input_file string, secret []byte, output_file string) {
	// Begin by reading in the bytes of our whole file into memory.

	// This works fine for small(er) files, but we're going to need to do something better for LARGE files.
	data, err := os.ReadFile(input_file)

	if err != nil {
		panic(err)
	}

	block, _ := aes.NewCipher(secret)

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		panic(err.Error())
	}

	// Generate a "nonce"  (number used once)
	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	writeErr := os.WriteFile(output_file, ciphertext, 0644)

	if writeErr != nil {
		panic(writeErr.Error())
	}

	fmt.Println(fmt.Sprintf("Successfully encrypted %v as %v.", input_file, output_file))
}

// Decrypts a given file.
func Decrypt(input_file string, secret []byte, output_file string) {
	ciphertext, err := os.ReadFile(input_file)

	if err != nil {
		log.Fatal(fmt.Sprintf("Error reading file contents from %v.", input_file))
	}

	block, _ := aes.NewCipher(secret)
	gcm, err := cipher.NewGCM(block)

	if err != nil {
		log.Fatal("Error creating the GCM cipher.")
	}

	// We need the nonce size for reading...
	nonceSize := gcm.NonceSize()

	if len(ciphertext) < nonceSize {
		log.Fatal("Nonce size cannot be larger than the length of the ciphertext.")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal("Issue reading the decrypted file contents...")
	}

	file_err := os.WriteFile(output_file, plaintext, 0644)

	if file_err != nil {
		log.Fatal(fmt.Sprintf("Error writing to decrypted file %v", output_file))
	}

	fmt.Println(fmt.Sprintf("Successfully decrypted %v as %v.", input_file, output_file))
}
