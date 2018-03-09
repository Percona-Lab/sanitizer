package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

type options struct {
	Command        string
	DecryptCommand *kingpin.CmdClause
	DecryptInFile  *string
	DecryptOutFile *string

	EncryptCommand *kingpin.CmdClause
	EncryptInFile  *string
	EncryptOutFile *string
}

func main() {
	app, opts, err := processCliParams()
	if err != nil {
		app.Usage([]string{})
		os.Exit(1)
	}

	fmt.Print("Please enter the password to decrypt the file:")
	passb, err := terminal.ReadPassword(0)
	if err != nil {
		fmt.Println("Cannot read the password form stdin")
		os.Exit(1)
	}
	password := sha256.Sum256(passb)

	switch opts.Command {
	case "decrypt":
		decrypt(*opts.DecryptInFile, *opts.DecryptOutFile, password)
	case "encrypt":
	}

}

func processCliParams() (*kingpin.Application, *options, error) {
	app := kingpin.New("encrypt-decrypt", "encrypt/decrypt sanitized data")
	opts := &options{
		DecryptCommand: app.Command("decrypt", "Decrypt an encrypted file."),
		EncryptCommand: app.Command("encrypt", "Encrypt a file."),
	}
	opts.DecryptInFile = opts.DecryptCommand.Arg("infile", "Encrypted file.").Required().String()
	opts.DecryptOutFile = opts.DecryptCommand.Arg("outfile", "Unencrypted file.").Required().String()

	opts.EncryptInFile = opts.EncryptCommand.Arg("infile", "Unencrypted file.").Required().String()
	opts.EncryptOutFile = opts.EncryptCommand.Arg("outfile", "Encrypted file.").Required().String()

	var err error
	opts.Command, err = app.Parse(os.Args[1:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "Cannot process command line parameters")
	}

	return app, opts, nil
}

func encrypt(infile, outfile string, pass [32]byte) {
	key := pass[:]
	inFile, err := os.Open(infile)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		panic(err)
	}
}
func decrypt(infile, outfile string, pass [32]byte) error {
	key := pass[:]
	inFile, err := os.Open(infile)
	if err != nil {
		return errors.Wrapf(err, "Cannot open %q for reading", infile)
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.Wrap(err, "Cannot create the cipher")
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrapf(err, "Cannot open %q for writing", outfile)
	}
	defer outFile.Close()

	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return errors.Wrapf(err, "Cannot write to %q", outfile)
	}
	return nil
}
