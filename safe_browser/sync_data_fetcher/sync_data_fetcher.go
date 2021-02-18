package main

import (
	b64 "encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	sync_chain_specs "github.com/brave/go-sync/safe_browser/sync_chain_specifics"
	"github.com/brave/go-sync/safe_browser/sync_crypto"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/golang/protobuf/proto"
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

func FetchPrefs(specs *sync_chain_specs.SyncChainSpecifics) {
	//NIGORI
	fmt.Println("NIGORI:")
	fmt.Println("___whole_message___")
	marker := getMarker([]int64{0}, []int32{nigoriType})
	msg := getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, true, nil)
	res_message, err := specs.MakeRequestToServer(msg)
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
	fmt.Println(len(salt))
	check(err)

	//KEYBAG:
	fmt.Println("___DECRYPTED_KEYBAG___")
	b, err := sync_crypto.AESCBCDecrypt(specs.EncKey, key_blob, specs.HmacKey)
	check(err)
	keybag := &sync_pb.NigoriKeyBag{}
	err = proto.Unmarshal(b, keybag)
	check(err)
	fmt.Println(proto.MarshalTextString(keybag))

	//prefferences
	fmt.Println("PREFFERENCES:")
	fmt.Println("___whole_message___")
	marker = getMarker([]int64{0}, []int32{prefsType})
	msg = getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, false, nil)
	res_message, err = specs.MakeRequestToServer(msg)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)

		check(err)
		p, err := sync_crypto.AESCBCDecrypt(specs.EncKey, pref_blob, specs.HmacKey)
		check(err)
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
	res_message, err = specs.MakeRequestToServer(msg)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p, err := sync_crypto.AESCBCDecrypt(specs.EncKey, pref_blob, specs.HmacKey)
		check(err)
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
	res_message, err = specs.MakeRequestToServer(msg)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p, err := sync_crypto.AESCBCDecrypt(specs.EncKey, pref_blob, specs.HmacKey)
		check(err)
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
	res_message, err = specs.MakeRequestToServer(msg)
	check(err)
	fmt.Println(proto.MarshalTextString(res_message))

	fmt.Println("___entries___")
	for _, entry := range res_message.GetUpdates.Entries {
		pref_blob, err := b64.StdEncoding.DecodeString(*entry.Specifics.GetEncrypted().Blob)
		check(err)
		p, err := sync_crypto.AESCBCDecrypt(specs.EncKey, pref_blob, specs.HmacKey)
		check(err)
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
	specs, err := sync_chain_specs.NewFromFile(&http.Client{}, "../sync_data_loader/sync_specs.json")
	check(err)

	FetchPrefs(specs)
}
