package main

import (
	"flag"
	"log"

	"gocrypt"
)

func main() {
	keygen := flag.Bool("keygen", false, "Generate a secret key.")
	encrypt := flag.String("encrypt", "", "The input file to be encrypted.")
	decrypt := flag.String("decrypt", "", "The input file to be decrypted.")
	key := flag.String("key", "", "The file containing the secret key.")
	pass := flag.String("pass", "", "The file password for the secret key.")
	output := flag.String("output", "", "The output file of a keygen, encryption, or decryption.")
	flag.Parse()

	if *keygen {
		if *output != "" {
			if *pass != "" {
				gocrypt.GenerateSecret(*pass, *output)
			} else {
				log.Fatal("A passphrase must be specified with -pass <passphrase>.")
			}
		} else {
			log.Fatal("An output file must be specified with -output <file_name>.")
		}
	} else if *encrypt != "" {
		if *output != "" {
			if *key != "" {
				secret := gocrypt.ReadSecret(*key)
				gocrypt.Encrypt(*encrypt, secret, *output)
			} else {
				log.Fatal("A secret key file must be specified with -k <file_name>.")
			}
		} else {
			log.Fatal("An output file must be specified with -output <file_name>.")
		}
	} else if *decrypt != "" {
		if *output != "" {
			if *key != "" {
				secret := gocrypt.ReadSecret(*key)
				gocrypt.Decrypt(*decrypt, secret, *output)
			} else {
				log.Fatal("A secret key file must be specified with -k <file_name>.")
			}
		} else {
			log.Fatal("An output file must be specified with -output <file_name>.")
		}
	}
}
