package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

const (
	sync_server_url             = "http://localhost:8295/sync/command/"
	bookmarkType         int32  = 32904
	prefsType            int32  = 37702
	nigoriType           int32  = 47745
	devInfoType          int32  = 154522
	sessionType          int32  = 50119
	cacheGUID            string = "cache_guid"
	passwordHashPrefName string = "safe_browser.password_hash"
)

func getMarker(tokens []int64, types []int32) []*sync_pb.DataTypeProgressMarker {
	if len(types) != len(tokens) {
		return nil
	}

	marker := []*sync_pb.DataTypeProgressMarker{}
	for i, token := range tokens {
		tokenBytes := make([]byte, binary.MaxVarintLen64)
		binary.PutVarint(tokenBytes, token)
		marker = append(marker, &sync_pb.DataTypeProgressMarker{
			DataTypeId: aws.Int32(types[i]), Token: tokenBytes})
	}
	return marker
}

func getClientToServerGUMsg(marker []*sync_pb.DataTypeProgressMarker,
	origin sync_pb.SyncEnums_GetUpdatesOrigin, fetchFolders bool,
	batchSize *int32) *sync_pb.ClientToServerMessage {
	guMsg := &sync_pb.GetUpdatesMessage{
		FetchFolders:       aws.Bool(fetchFolders),
		FromProgressMarker: marker,
		GetUpdatesOrigin:   &origin,
		BatchSize:          batchSize,
	}
	contents := sync_pb.ClientToServerMessage_GET_UPDATES
	return &sync_pb.ClientToServerMessage{
		MessageContents: &contents,
		GetUpdates:      guMsg,
		Share:           aws.String("?"),
	}
}

func getClientToServerCommitMsg(entries []*sync_pb.SyncEntity) *sync_pb.ClientToServerMessage {
	commitMsg := &sync_pb.CommitMessage{
		Entries: entries,
	}
	commit := sync_pb.ClientToServerMessage_COMMIT
	return &sync_pb.ClientToServerMessage{
		MessageContents: &commit,
		Commit:          commitMsg,
		Share:           aws.String("?"),
	}
}

func initReq(client *http.Client, token string) (*sync_pb.ClientToServerResponse, error) {
	newClient := sync_pb.SyncEnums_NEW_CLIENT
	updates := &sync_pb.GetUpdatesMessage{
		GetUpdatesOrigin: &newClient,
	}

	getUpdates := sync_pb.ClientToServerMessage_GET_UPDATES
	msg := &sync_pb.ClientToServerMessage{
		MessageContents: &getUpdates,
		GetUpdates:      updates,
		Share:           aws.String(""),
	}

	return makeRequestToServer(client, token, msg)
}

func makeRequestToServer(client *http.Client, token string, msg *sync_pb.ClientToServerMessage) (*sync_pb.ClientToServerResponse, error) {
	res_message := &sync_pb.ClientToServerResponse{}
	body, err := proto.Marshal(msg)

	if err != nil {
		return res_message, err
	}

	req, err := http.NewRequest("POST", sync_server_url, bytes.NewBuffer(body))
	if err != nil {
		return res_message, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return res_message, err
	}

	if res.StatusCode != 200 {
		return res_message, errors.New(res.Status)
	}
	fmt.Println(res.Status)

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return res_message, err
	}

	err = proto.Unmarshal(res_body, res_message)

	return res_message, err
}

func getEncryptedData(msg []byte, enc_key []byte, hmac_key []byte, key_name string) (*sync_pb.EncryptedData, error) {

	encrypted_data := &sync_pb.EncryptedData{}

	encrypted, err := utils.AESCBCEncrypt(enc_key, msg, hmac_key)
	if err != nil {
		return encrypted_data, err
	}

	encoded := b64.StdEncoding.EncodeToString(encrypted)

	encrypted_data.KeyName = aws.String(key_name)
	encrypted_data.Blob = aws.String(encoded)

	return encrypted_data, nil
}

func updateNigoriWithEncryptionData(client *http.Client, token string, enc_key []byte, hmac_key []byte, salt []byte, key_name string) (*sync_pb.ClientToServerResponse, error) {
	res_message := &sync_pb.ClientToServerResponse{}

	zeroez := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	marker := getMarker([]int64{0}, []int32{nigoriType})
	msg := getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, true, nil)
	response, err := makeRequestToServer(client, token, msg)
	if err != nil {
		return res_message, err
	}

	nigoriEntry := response.GetUpdates.Entries[0]

	nigori := nigoriEntry.Specifics.GetNigori()

	keyBag := &sync_pb.NigoriKeyBag{
		Key: []*sync_pb.NigoriKey{
			{
				DeprecatedName:    aws.String(key_name),
				DeprecatedUserKey: zeroez,
				EncryptionKey:     enc_key,
				MacKey:            hmac_key,
			},
		},
	}

	encryption_keybag, err := proto.Marshal(keyBag)
	if err != nil {
		return res_message, err
	}
	encrypted_data, err := getEncryptedData(encryption_keybag, enc_key, hmac_key, key_name)
	if err != nil {
		return res_message, err
	}

	nigori.EncryptionKeybag = encrypted_data
	nigori.CustomPassphraseKeyDerivationSalt = aws.String(b64.StdEncoding.EncodeToString(salt))
	nigori.CustomPassphraseKeyDerivationMethod = aws.Int32(2)
	nigori.KeystoreMigrationTime = aws.Int64(utils.GetCTime())
	nigori.PassphraseType = aws.Int32(4)
	nigori.CustomPassphraseTime = aws.Int64(utils.GetCTime())
	nigori.KeybagIsFrozen = aws.Bool(true)
	nigori.EncryptBookmarks = aws.Bool(true)
	nigori.EncryptPreferences = aws.Bool(true)
	nigori.EncryptAutofill = aws.Bool(true)
	nigori.EncryptAutofillProfile = aws.Bool(true)
	nigori.EncryptThemes = aws.Bool(true)
	nigori.EncryptTypedUrls = aws.Bool(true)
	nigori.EncryptExtensions = aws.Bool(true)
	nigori.EncryptApps = aws.Bool(true)
	nigori.EncryptSearchEngines = aws.Bool(true)
	nigori.EncryptSessions = aws.Bool(true)
	nigori.EncryptEverything = aws.Bool(true)
	nigori.EncryptExtensionSettings = aws.Bool(true)
	nigori.EncryptAppSettings = aws.Bool(true)
	nigori.EncryptDictionary = aws.Bool(true)
	nigori.EncryptFaviconImages = aws.Bool(true)
	nigori.EncryptFaviconTracking = aws.Bool(true)
	nigori.EncryptAppList = aws.Bool(true)
	nigori.EncryptAutofillWalletMetadata = aws.Bool(true)
	nigori.EncryptArcPackage = aws.Bool(true)
	nigori.EncryptPrinters = aws.Bool(true)
	nigori.EncryptReadingList = aws.Bool(true)
	nigori.EncryptWebApps = aws.Bool(true)
	nigori.EncryptOsPreferences = aws.Bool(true)

	nigoriEntry.Specifics = &sync_pb.EntitySpecifics{
		SpecificsVariant: &sync_pb.EntitySpecifics_Nigori{
			Nigori: nigori,
		},
	}

	entries := []*sync_pb.SyncEntity{
		nigoriEntry,
	}

	msg = getClientToServerCommitMsg(entries)

	res_message, err = makeRequestToServer(client, token, msg)

	return res_message, nil
}

func saveSyncData(seedHex string, mnemonic string, seed []byte, cache_id string) error {
	err := qrcode.WriteFile(seedHex, qrcode.Medium, 300, "qr.png")
	err = ioutil.WriteFile("code.txt", []byte(mnemonic), 0644)
	err = ioutil.WriteFile("seed.txt", seed, 0644)
	err = ioutil.WriteFile("cache_id.txt", []byte(cache_id), 0644)
	return err

}

func loadSettings(client *http.Client, token string, enc_key []byte, hmac_key []byte, key_name string, cache_id string) (*sync_pb.ClientToServerResponse, error) {
	res_message := &sync_pb.ClientToServerResponse{}
	password_prefs := &sync_pb.PreferenceSpecifics{}
	pass_hash := utils.GenRandomBytes(32)
	id, err := uuid.NewRandom()
	if err != nil {
		return res_message, err
	}

	client_item_id, err := uuid.NewRandom()
	if err != nil {
		return res_message, err
	}

	uniqueTag := utils.GenRandomBytes(20)

	password_prefs.Name = aws.String(passwordHashPrefName)
	password_prefs.Value = aws.String(b64.StdEncoding.EncodeToString(pass_hash))

	prefs_bytes, err := proto.Marshal(password_prefs)
	if err != nil {
		return res_message, err
	}

	encrypted_data, err := getEncryptedData(prefs_bytes, enc_key, hmac_key, key_name)
	if err != nil {
		return res_message, err
	}

	entity := &sync_pb.SyncEntity{}
	entity.IdString = aws.String(id.String())
	entity.Version = aws.Int64(0)
	entity.Name = aws.String("encrypted")
	entity.Deleted = aws.Bool(false)
	entity.OriginatorCacheGuid = aws.String(cache_id)
	entity.OriginatorClientItemId = aws.String(client_item_id.String())
	entity.Folder = aws.Bool(false)
	entity.ClientDefinedUniqueTag = aws.String(b64.StdEncoding.EncodeToString(uniqueTag))
	entity.Ctime = aws.Int64(utils.GetCTime())
	entity.Mtime = entity.Ctime
	entity.Specifics = &sync_pb.EntitySpecifics{
		Encrypted: encrypted_data,
		SpecificsVariant: &sync_pb.EntitySpecifics_Preference{
			Preference: &sync_pb.PreferenceSpecifics{},
		},
	}

	entries := []*sync_pb.SyncEntity{
		entity,
	}

	msg := getClientToServerCommitMsg(entries)
	fmt.Println(proto.MarshalTextString(msg))

	return makeRequestToServer(client, token, msg)
}

func getCacheId() (string, error) {
	cache_id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	bytes, err := cache_id.MarshalBinary()
	if err != nil {
		return "", err
	}

	return b64.StdEncoding.EncodeToString(bytes), nil
}

func CreateDummyData() {
	client := &http.Client{}

	seed := utils.GenRandomBytes(32)
	salt := utils.GenRandomBytes(32)

	enc_key, hmac_key, err := utils.GetEncAndHmacKey(seed, salt)
	check(err)

	key_name, err := utils.GenerateKeyName(enc_key, hmac_key)
	fmt.Println(key_name)

	prk, puk, err := utils.GenerateSigningKeys(seed)
	check(err)

	token, err := utils.GenerateToken(puk, prk, utils.UnixMilli(time.Now()))
	check(err)

	mnemonic, err := utils.GetMnemonic(seed)
	check(err)
	seedHex := strings.ToUpper(hex.EncodeToString(seed))
	check(err)
	cache_id, err := getCacheId()

	err = saveSyncData(seedHex, mnemonic, seed, cache_id)
	check(err)

	_, err = initReq(client, token)
	check(err)

	_, err = updateNigoriWithEncryptionData(client, token, enc_key, hmac_key, salt, key_name)
	check(err)

	_, err = loadSettings(client, token, enc_key, hmac_key, key_name, cache_id)
	check(err)
}

func main() {
	CreateDummyData()
}
