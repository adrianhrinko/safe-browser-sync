package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

func GenerateSigningKeys(seed []byte) ([]byte, []byte, error) {
	salt := []byte{
		72, 203, 156, 43, 64, 229, 225, 127, 214, 158, 50, 29, 130,
		186, 182, 207, 6, 108, 47, 254, 245, 71, 198, 109, 44, 108,
		32, 193, 221, 126, 119, 143, 112, 113, 87, 184, 239, 231, 230,
		234, 28, 135, 54, 42, 9, 243, 39, 30, 179, 147, 194, 211,
		212, 239, 225, 52, 192, 219, 145, 40, 95, 19, 142, 98}
	info := []byte("sync-auth-key")
	r := hkdf.New(sha512.New, seed, salt, info)

	publicKey, privateKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key error: %w", err)
	}

	return privateKey, publicKey, nil
}

func GenerateToken(publicKey []byte, privateKey []byte, timestamp int64) (string, error) {
	timestampBytes := []byte(strconv.FormatInt(timestamp, 10))

	signedTimestampBytes := ed25519.Sign(privateKey, timestampBytes)
	publicKeyHex := strings.ToUpper(hex.EncodeToString(publicKey))

	token := hex.EncodeToString(timestampBytes) + "|" +
		hex.EncodeToString(signedTimestampBytes) + "|" + publicKeyHex

	return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

func ValidMAC(message, messageMAC, key []byte) bool {
	expectedMAC := GetMAC(message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}

func GetMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func AESCBCDecrypt(encr_key []byte, ciphertext []byte, hmac_key []byte) []byte {

	block, err := aes.NewCipher(encr_key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < 2*aes.BlockSize+32 {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	hmac := ciphertext[(len(ciphertext) - 32):]
	to_decrypt := ciphertext[aes.BlockSize:(len(ciphertext) - 32)]

	if !ValidMAC(to_decrypt, hmac, hmac_key) {
		panic("Invalid MAC")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(to_decrypt, to_decrypt)

	//remove pad
	pad_len := int(to_decrypt[len(to_decrypt)-1])
	if int(to_decrypt[len(to_decrypt)-pad_len]) == pad_len {
		to_decrypt = to_decrypt[:(len(to_decrypt) - pad_len)]
	}

	return to_decrypt
}

func AESCBCEncrypt(encr_key []byte, plaintext []byte, hmac_key []byte) []byte {

	iv := make([]byte, len(encr_key))
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	ciphertext := AESCBCEncryptBasic(iv, encr_key, plaintext)

	mac := GetMAC(ciphertext, hmac_key)
	ciphertext = append(iv, ciphertext...)
	ciphertext = append(ciphertext, mac...)

	return ciphertext
}

func AESCBCEncryptBasic(iv []byte, encr_key []byte, plaintext []byte) []byte {

	if len(iv) != len(encr_key) {
		panic("len(iv) != len(encr_key)")
	}

	padded_plaintext := plaintext
	//pad
	if len(plaintext)%aes.BlockSize != 0 {
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		padded_plaintext = append(plaintext, padtext...)
	}

	block, err := aes.NewCipher(encr_key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(padded_plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded_plaintext)

	return ciphertext
}
