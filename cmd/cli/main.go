package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	publicKeyPath     string
	privateKeyPath    string
	passphrase        string
	message           string
	messagePath       string
	messageOutputPath string
)

func init() {
	cmdEncrypt.Flags().StringVarP(&publicKeyPath, "public-key-path", "u", "", "absolute or relative path to public key file")
	cmdEncrypt.Flags().StringVarP(&message, "message", "m", "", "message to encrypt")
	cmdEncrypt.Flags().StringVar(&messagePath, "message-path", "", "absolute or relative path to a file from where message will be red for encryption")
	cmdEncrypt.Flags().StringVarP(&messageOutputPath, "message-output-path", "o", "", "absolute or relative path to a file where encrypted message will be saved, if left empty then message will be printed to stdout. File will be created if it doesn't exist, or truncated if it exists")

	cmdDecrypt.Flags().StringVarP(&privateKeyPath, "private-key-path", "r", "", "absolute or relative path to private key file")
	cmdDecrypt.Flags().StringVarP(&passphrase, "passphrase", "p", "", "passphrase that was used to encrypt private key file")
	cmdDecrypt.Flags().StringVarP(&message, "message", "m", "", "message to decrypt")
	cmdDecrypt.Flags().StringVar(&messagePath, "message-path", "", "absolute or relative path to a file from where message will be red for decryption")
	cmdDecrypt.Flags().StringVarP(&messageOutputPath, "message-output-path", "o", "", "absolute or relative path to a file where decrypted message will be saved, if left empty then message will be printed to stdout. File will be created if it doesn't exist, or truncated if it exists")
}

var rootCmd = &cobra.Command{
	Use:   "secure-cli",
	Short: "secure-cli is a tool to encrypt/decrypt message using RSA technique.",
	Long: `secure-cli is a tool to encrypt/decrypt message using RSA technique.
So, that only you and intended receiver can read the message.
`,
	Example: `secure-cli encrypt --public-key-path /path/to/file --message my-message
secure-cli decrypt --private-key-path /path/to/file --passphrase my-passphrase --message my-message`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Usage()
	},
}

var cmdEncrypt = &cobra.Command{
	Use:   "encrypt --public-key-path /path/to/file --message my-message",
	Short: "Encrypt a message",
	Long: `Encrypt a message.

NOTE: message will be base64 encoded.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if publicKeyPath == "" {
			return errors.New("path to public key file can't be empty")
		}
		if message == "" && messagePath == "" {
			return errors.New("message to encrypt and path to a message file can't be empty")
		}

		if messagePath != "" {
			messageRaw, err := os.ReadFile(messagePath)
			if err != nil {
				return fmt.Errorf("failed to read message file: %w", err)
			}
			message = string(messageRaw)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		} else if len(b) == 0 {
			return errors.New("empty public key file")
		}

		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("invalid public key file")
		}

		publicKeyRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key file: %w", err)
		}

		publicKey := *publicKeyRaw.(*rsa.PublicKey)

		encryptedMessage, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, &publicKey, []byte(message), nil)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}

		encryptedMessage = []byte(base64.StdEncoding.EncodeToString(encryptedMessage))

		file := os.Stdout
		if messageOutputPath != "" {
			file, err = os.OpenFile(messageOutputPath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
			if err != nil {
				// just print the error and print output in stdout
				fmt.Printf("failed to open output file: %v\n", err)
				file = os.Stdout
			}
		}

		fmt.Fprintf(file, string(encryptedMessage))

		return nil
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

var cmdDecrypt = &cobra.Command{
	Use:   "decrypt --private-key-path /path/to/file --passphrase my-passphrase --message my-message",
	Short: "Decrypt a message",
	Long: `Decrypt a message.

NOTE: message has to be base64 encoded`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if privateKeyPath == "" {
			return errors.New("path to private key file can't be empty")
		}
		if passphrase == "" {
			return errors.New("passphrase can't be empty")
		}
		if message == "" && messagePath == "" {
			return errors.New("message to decrypt and path to a message file can't be empty")
		}

		if messagePath != "" {
			messageRaw, err := os.ReadFile(messagePath)
			if err != nil {
				return fmt.Errorf("failed to read message file: %w", err)
			}
			messageRaw, err = base64.StdEncoding.DecodeString(string(messageRaw))
			if err != nil {
				return fmt.Errorf("failed to base64 decode message file: %w", err)
			}
			message = string(messageRaw)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		} else if len(b) == 0 {
			return errors.New("empty private key file")
		}

		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("invalid private key file")
		}

		privateKeyRaw, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("failed to decrypt private key file: %w", err)
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyRaw)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		decryptedMessage, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, []byte(message), nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt message: %w", err)
		}

		file := os.Stdout
		if messageOutputPath != "" {
			file, err = os.OpenFile(messageOutputPath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
			if err != nil {
				// just print the error and print output in stdout
				fmt.Printf("failed to open output file: %v\n", err)
				file = os.Stdout
			}
		}

		fmt.Fprintf(file, string(decryptedMessage))

		return nil
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

func main() {
	rootCmd.AddCommand(cmdEncrypt, cmdDecrypt)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
