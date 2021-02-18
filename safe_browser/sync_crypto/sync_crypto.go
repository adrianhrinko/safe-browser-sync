package sync_crypto

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
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/cosmos/go-bip39"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

func GenRandomBytes(size int) []byte {
	seed := make([]byte, size)
	rand.Read(seed)
	return seed
}

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

func AESCBCDecrypt(encr_key []byte, ciphertext []byte, hmac_key []byte) ([]byte, error) {

	block, err := aes.NewCipher(encr_key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 2*aes.BlockSize+32 {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	hmac := ciphertext[(len(ciphertext) - 32):]
	to_decrypt := ciphertext[aes.BlockSize:(len(ciphertext) - 32)]

	if !ValidMAC(to_decrypt, hmac, hmac_key) {
		return nil, errors.New("Invalid MAC")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(to_decrypt, to_decrypt)

	//remove pad
	pad_len := int(to_decrypt[len(to_decrypt)-1])
	if int(to_decrypt[len(to_decrypt)-pad_len]) == pad_len {
		to_decrypt = to_decrypt[:(len(to_decrypt) - pad_len)]
	}

	return to_decrypt, nil
}

func AESCBCEncrypt(encr_key []byte, plaintext []byte, hmac_key []byte) ([]byte, error) {

	iv := make([]byte, len(encr_key))
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext, err := AESCBCEncryptBasic(iv, encr_key, plaintext)

	if err != nil {
		return nil, err
	}

	mac := GetMAC(ciphertext, hmac_key)
	ciphertext = append(iv, ciphertext...)
	ciphertext = append(ciphertext, mac...)

	return ciphertext, nil
}

func AESCBCEncryptBasic(iv []byte, encr_key []byte, plaintext []byte) ([]byte, error) {

	if len(iv) != len(encr_key) {
		return nil, errors.New("len(iv) != len(encr_key)")
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
		return nil, err
	}

	ciphertext := make([]byte, len(padded_plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded_plaintext)

	return ciphertext, nil
}

func GenerateKeyName(enc_key []byte, mac_key []byte) (string, error) {
	nigori_key_name := "nigori-key"
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	type_size_bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(type_size_bytes, 4)
	key_type_bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(key_type_bytes, 1)

	nigori_key_name_length_bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nigori_key_name_length_bytes, uint32(len(nigori_key_name)))
	nigori_key_name_bytes := []byte(nigori_key_name)

	result := append(type_size_bytes, key_type_bytes...)
	result = append(result, nigori_key_name_length_bytes...)
	result = append(result, nigori_key_name_bytes...)

	ciphertext, err := AESCBCEncryptBasic(iv, enc_key, result)
	if err != nil {
		return "", err
	}

	mac := GetMAC(ciphertext, mac_key)
	ciphertext = append(ciphertext, mac...)

	return b64.StdEncoding.EncodeToString(ciphertext), nil
}

func GetMnemonic(seed []byte) (string, error) {
	return bip39.NewMnemonic(seed)
}

func Scrypt(input []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(input, salt, 8192, 8, 11, 32)
}

func GetEncAndHmacKey(seed []byte, salt []byte) ([]byte, []byte, error) {
	mnemonic, err := GetMnemonic(seed)
	if err != nil {
		return nil, nil, err
	}

	enc_key_n_mac_key, err := Scrypt([]byte(mnemonic), salt)
	if err != nil {
		return nil, nil, err
	}

	enc_key := enc_key_n_mac_key[:16]
	mac_key := enc_key_n_mac_key[16:]

	return enc_key, mac_key, nil
}
