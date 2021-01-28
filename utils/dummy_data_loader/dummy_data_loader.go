package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/cosmos/go-bip39"
	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func CreateDummyData() {
	seed := make([]byte, 32)
	rand.Read(seed)

	prk, puk, err := utils.GenerateSigningKeys(seed)
	check(err)

	token, err := utils.GenerateToken(puk, prk, utils.UnixMilli(time.Now()))
	check(err)

	mnemonic, err := bip39.NewMnemonic(seed)
	check(err)

	seedHex := strings.ToUpper(hex.EncodeToString(seed))
	err = qrcode.WriteFile(seedHex, qrcode.Medium, 300, "qr.png")
	check(err)
	err = ioutil.WriteFile("code.txt", []byte(mnemonic), 0644)
	check(err)
	err = ioutil.WriteFile("seed.txt", seed, 0644)
	check(err)

	client := &http.Client{}

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

	body, err := proto.Marshal(msg)

	req, err := http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	check(err)
	fmt.Println(res.Status)

	commitMsg := &sync_pb.CommitMessage{
		Entries: []*sync_pb.SyncEntity{
			{
				IdString:               aws.String("bkmrk_01"),
				Name:                   aws.String("bkmrk_01"),
				Version:                aws.Int64(0),
				Deleted:                aws.Bool(false),
				Folder:                 aws.Bool(false),
				ClientDefinedUniqueTag: aws.String("clnt_01"),
				Specifics: &sync_pb.EntitySpecifics{
					SpecificsVariant: &sync_pb.EntitySpecifics_Bookmark{
						Bookmark: &sync_pb.BookmarkSpecifics{
							Url:       aws.String("https://azure.microsoft.com/en-us/features/azure-portal/"),
							FullTitle: aws.String("Azure Portal"),
						},
					},
				},
			},
		},
		CacheGuid: aws.String("cache_guid"),
	}

	commit := sync_pb.ClientToServerMessage_COMMIT
	msg = &sync_pb.ClientToServerMessage{
		MessageContents: &commit,
		Commit:          commitMsg,
		Share:           aws.String(""),
	}

	body, err = proto.Marshal(msg)

	req, err = http.NewRequest("POST", "http://localhost:8295/sync/command/", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = client.Do(req)
	check(err)
	fmt.Println(res.Status)

}

func main() {
	CreateDummyData()
}
