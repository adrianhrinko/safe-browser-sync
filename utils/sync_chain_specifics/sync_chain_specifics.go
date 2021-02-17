package sync_chain_specs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"
)

//SyncChainSpecifics stores sync chain specific data
type SyncChainSpecifics struct {
	client      *http.Client `json:"-"`
	serverURL   string       `json:"serverURL"`
	cacheGUID   string       `json:"cacheGUID"`
	seed        []byte       `json:"seed"`
	salt        []byte       `json:"salt"`
	encKey      []byte       `json:"-"`
	hmaKey      []byte       `json:"-"`
	keyName     string       `json:"-"`
	prK         []byte       `json:"-"`
	puK         []byte       `json:"-"`
	initialized bool         `json:"-"`
}

// New creates new SyncChainSpecifics struct
func New(client *http.Client, serverURL string) (*SyncChainSpecifics, error) {
	syncChainSpecs := &SyncChainSpecifics{}

	seed := utils.GenRandomBytes(32)
	salt := utils.GenRandomBytes(32)

	encKey, hmacKey, err := utils.GetEncAndHmacKey(seed, salt)
	if err != nil {
		return nil, err
	}

	keyName, err := utils.GenerateKeyName(encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	prK, puK, err := utils.GenerateSigningKeys(seed)
	if err != nil {
		return nil, err
	}

	cacheGUID, err := getCacheGUID()
	if err != nil {
		return nil, err
	}

	syncChainSpecs.client = client
	syncChainSpecs.serverURL = serverURL
	syncChainSpecs.cacheGUID = cacheGUID
	syncChainSpecs.seed = seed
	syncChainSpecs.salt = salt
	syncChainSpecs.encKey = encKey
	syncChainSpecs.hmaKey = hmacKey
	syncChainSpecs.keyName = keyName
	syncChainSpecs.prK = prK
	syncChainSpecs.puK = puK
	syncChainSpecs.initialized = false

	return syncChainSpecs, nil
}

//NewFromDisc creates new SyncChainSpecifics struct from file
func NewFromFile(client *http.Client, specificsFileName string) (*SyncChainSpecifics, error) {

	specificsFile, err := os.Open(specificsFileName)
	if err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadAll(specificsFile)
	if err != nil {
		return nil, err
	}

	syncChainSpecs := &SyncChainSpecifics{}

	err = json.Unmarshal(byteValue, syncChainSpecs)
	if err != nil {
		return nil, err
	}

	encKey, hmacKey, err := utils.GetEncAndHmacKey(syncChainSpecs.seed, syncChainSpecs.salt)
	if err != nil {
		return nil, err
	}

	keyName, err := utils.GenerateKeyName(encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	prK, puK, err := utils.GenerateSigningKeys(syncChainSpecs.seed)
	if err != nil {
		return nil, err
	}

	syncChainSpecs.client = client
	syncChainSpecs.encKey = encKey
	syncChainSpecs.hmaKey = hmacKey
	syncChainSpecs.keyName = keyName
	syncChainSpecs.prK = prK
	syncChainSpecs.puK = puK
	syncChainSpecs.initialized = false

	return syncChainSpecs, nil
}

func (s SyncChainSpecifics) init() (*sync_pb.ClientToServerResponse, error) {
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

	res, err := s.makeRequestToServer(msg)

	if err != nil {
		return nil, err
	}

	s.initialized = true

	return res, nil
}

func (s SyncChainSpecifics) getToken() (string, error) {
	return utils.GenerateToken(s.puK, s.prK, utils.UnixMilli(time.Now()))
}

func (s SyncChainSpecifics) getSeedHex() string {
	return strings.ToUpper(hex.EncodeToString(s.seed))
}

func (s SyncChainSpecifics) getSyncMnemonic() (string, error) {
	return utils.GetMnemonic(s.seed)
}

func (s SyncChainSpecifics) makeRequestToServer(msg *sync_pb.ClientToServerMessage) (*sync_pb.ClientToServerResponse, error) {
	resMessage := &sync_pb.ClientToServerResponse{}
	body, err := proto.Marshal(msg)

	if err != nil {
		return resMessage, err
	}

	req, err := http.NewRequest("POST", s.serverURL, bytes.NewBuffer(body))
	if err != nil {
		return resMessage, err
	}

	token, err := s.getToken()
	if err != nil {
		return resMessage, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	res, err := s.client.Do(req)
	if err != nil {
		return resMessage, err
	}

	if res.StatusCode != 200 {
		return resMessage, errors.New(res.Status)
	}
	fmt.Println(res.Status)

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return resMessage, err
	}

	err = proto.Unmarshal(resBody, resMessage)

	return resMessage, err
}

func (s SyncChainSpecifics) saveToFile(specsFileName string, qrCodeFileName *string) error {
	output, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(specsFileName, output, 0644)
}

func (s SyncChainSpecifics) getSyncQRCode() ([]byte, error) {
	return qrcode.Encode(s.getSeedHex(), qrcode.Medium, 300)
}

func (s SyncChainSpecifics) saveSyncQRCodeToFile(qrCodeFileName string) error {
	return qrcode.WriteFile(s.getSeedHex(), qrcode.Medium, 300, qrCodeFileName)
}

func (s SyncChainSpecifics) saveSyncMnemonicToFile(mnemonicFileName string) error {
	mnemonic, err := s.getSyncMnemonic()

	if err != nil {
		return err
	}

	return ioutil.WriteFile(mnemonicFileName, []byte(mnemonic), 0644)
}

func getCacheGUID() (string, error) {
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
