package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/cosmos/go-bip39"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/scrypt"
)

const (
	bookmarkType int32  = 32904
	prefsType    int32  = 37702
	nigoriType   int32  = 47745
	devInfoType  int32  = 154522
	sessionType  int32  = 50119
	cacheGUID    string = "cache_guid"
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
		Share:           aws.String("yeah!"),
	}
}

func FetchPrefs(seed []byte) {
	prk, puk, err := utils.GenerateSigningKeys(seed)
	check(err)

	token, err := utils.GenerateToken(puk, prk, utils.UnixMilli(time.Now()))
	check(err)

	client := &http.Client{}

	//NIGORI
	fmt.Println("NIGORI:")
	fmt.Println("___whole_message___")
	marker := getMarker([]int64{0}, []int32{nigoriType})
	msg := getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, true, nil)
	body, err := proto.Marshal(msg)
	req, err := http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	check(err)
	if res.StatusCode != 200 {
		panic(errors.New(res.Status))
	}
	fmt.Println(res.Status)

	res_body, err := ioutil.ReadAll(res.Body)
	check(err)
	res_message := &sync_pb.ClientToServerResponse{}
	err = proto.Unmarshal(res_body, res_message)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	if len(res_message.GetUpdates.Entries) != 1 && strings.Contains(strings.ToLower(*res_message.GetUpdates.Entries[0].Name), "nigori") {
		panic(errors.New("something went wrong, there is no nigori in the db"))
	}

	nigori := res_message.GetUpdates.Entries[0].Specifics.GetNigori()
	encryption_keybag := nigori.EncryptionKeybag
	check(err)
	key_name := *encryption_keybag.KeyName
	key_blob, err := b64.StdEncoding.DecodeString(*encryption_keybag.Blob)

	fmt.Println(key_name)
	check(err)
	salt, err := b64.StdEncoding.DecodeString(*nigori.CustomPassphraseKeyDerivationSalt)
	check(err)

	mnemonic, err := bip39.NewMnemonic(seed)
	check(err)

	enc_key_n_mac_key, err := scrypt.Key([]byte(mnemonic), salt, 8192, 8, 11, 32)
	check(err)
	enc_key := enc_key_n_mac_key[:16]
	mac_key := enc_key_n_mac_key[16:]

	//KEYBAG:
	fmt.Println("___DECRYPTED_KEYBAG___")
	b := utils.AESCBCDecrypt(enc_key, key_blob, mac_key)
	keybag := &sync_pb.NigoriKeyBag{}
	err = proto.Unmarshal(b, keybag)
	check(err)
	fmt.Println(proto.MarshalTextString(keybag))

	//prefferences
	fmt.Println("PREFFERENCES:")
	fmt.Println("___whole_message___")
	marker = getMarker([]int64{0}, []int32{prefsType})
	msg = getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, false, nil)
	body, err = proto.Marshal(msg)
	req, err = http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = client.Do(req)
	check(err)
	if res.StatusCode != 200 {
		panic(errors.New(res.Status))
	}
	fmt.Println(res.Status)

	res_body, err = ioutil.ReadAll(res.Body)
	check(err)
	res_message = &sync_pb.ClientToServerResponse{}
	err = proto.Unmarshal(res_body, res_message)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p := utils.AESCBCDecrypt(enc_key, pref_blob, mac_key)
		pref := &sync_pb.EntitySpecifics{}
		err = proto.Unmarshal(p, pref)
		check(err)
		fmt.Println(proto.MarshalTextString(pref))
		fmt.Println("_____________________________________")
	}

	//dev info
	fmt.Println("DEVICES:")
	fmt.Println("___whole_message___")
	marker = getMarker([]int64{0}, []int32{devInfoType})
	msg = getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, false, nil)
	body, err = proto.Marshal(msg)
	req, err = http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = client.Do(req)
	check(err)
	if res.StatusCode != 200 {
		panic(errors.New(res.Status))
	}
	fmt.Println(res.Status)

	res_body, err = ioutil.ReadAll(res.Body)
	check(err)
	res_message = &sync_pb.ClientToServerResponse{}
	err = proto.Unmarshal(res_body, res_message)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p := utils.AESCBCDecrypt(enc_key, pref_blob, mac_key)
		pref := &sync_pb.EntitySpecifics{}
		err = proto.Unmarshal(p, pref)
		check(err)
		fmt.Println(proto.MarshalTextString(pref))
		fmt.Println("_____________________________________")
	}

	//sessions
	fmt.Println("SESSIONS:")
	fmt.Println("___whole_message___")
	marker = getMarker([]int64{0}, []int32{sessionType})
	msg = getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, false, nil)
	body, err = proto.Marshal(msg)
	req, err = http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = client.Do(req)
	check(err)
	if res.StatusCode != 200 {
		panic(errors.New(res.Status))
	}
	fmt.Println(res.Status)

	res_body, err = ioutil.ReadAll(res.Body)
	check(err)
	res_message = &sync_pb.ClientToServerResponse{}
	err = proto.Unmarshal(res_body, res_message)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p := utils.AESCBCDecrypt(enc_key, pref_blob, mac_key)
		pref := &sync_pb.EntitySpecifics{}
		err = proto.Unmarshal(p, pref)
		check(err)
		fmt.Println(proto.MarshalTextString(pref))
		fmt.Println("_____________________________________")
	}

	//BOOKMARKS
	fmt.Println("BOOKMARKS:")
	fmt.Println("___whole_message___")
	marker = getMarker([]int64{0}, []int32{bookmarkType})
	msg = getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, false, nil)
	body, err = proto.Marshal(msg)
	req, err = http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = client.Do(req)
	check(err)
	if res.StatusCode != 200 {
		panic(errors.New(res.Status))
	}
	fmt.Println(res.Status)

	res_body, err = ioutil.ReadAll(res.Body)
	check(err)
	res_message = &sync_pb.ClientToServerResponse{}
	err = proto.Unmarshal(res_body, res_message)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p := utils.AESCBCDecrypt(enc_key, pref_blob, mac_key)
		pref := &sync_pb.EntitySpecifics{}
		err = proto.Unmarshal(p, pref)
		check(err)
		fmt.Println(proto.MarshalTextString(pref))
		fmt.Println("_____________________________________")
	}

}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	seed, err := ioutil.ReadFile("../dummy_data_loader/seed.txt")
	check(err)
	if seed == nil {
		panic(errors.New("seed is null!"))
	}

	FetchPrefs(seed)
}
