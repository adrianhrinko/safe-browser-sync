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
	"github.com/brave/go-sync/safe_browser/sync_crypto"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"
)

//SyncChainSpecifics stores sync chain specific data
type SyncChainSpecifics struct {
	Client      *http.Client `json:"-"`
	ServerURL   string       `json:"serverURL"`
	CacheGUID   string       `json:"cacheGUID"`
	Seed        []byte       `json:"seed"`
	Salt        []byte       `json:"salt"`
	EncKey      []byte       `json:"-"`
	HmacKey     []byte       `json:"-"`
	KeyName     string       `json:"-"`
	PrK         []byte       `json:"-"`
	PuK         []byte       `json:"-"`
	Initialized bool         `json:"-"`
}

// New creates new SyncChainSpecifics struct
func New(client *http.Client, serverURL string) (*SyncChainSpecifics, error) {
	syncChainSpecs := &SyncChainSpecifics{}

	seed := sync_crypto.GenRandomBytes(32)
	salt := sync_crypto.GenRandomBytes(32)

	encKey, hmacKey, err := sync_crypto.GetEncAndHmacKey(seed, salt)
	if err != nil {
		return nil, err
	}

	keyName, err := sync_crypto.GenerateKeyName(encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	prK, puK, err := sync_crypto.GenerateSigningKeys(seed)
	if err != nil {
		return nil, err
	}

	cacheGUID, err := getCacheGUID()
	if err != nil {
		return nil, err
	}

	syncChainSpecs.Client = client
	syncChainSpecs.ServerURL = serverURL
	syncChainSpecs.CacheGUID = cacheGUID
	syncChainSpecs.Seed = seed
	syncChainSpecs.Salt = salt
	syncChainSpecs.EncKey = encKey
	syncChainSpecs.HmacKey = hmacKey
	syncChainSpecs.KeyName = keyName
	syncChainSpecs.PrK = prK
	syncChainSpecs.PuK = puK
	syncChainSpecs.Initialized = false

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

	encKey, hmacKey, err := sync_crypto.GetEncAndHmacKey(syncChainSpecs.Seed, syncChainSpecs.Salt)
	if err != nil {
		return nil, err
	}

	keyName, err := sync_crypto.GenerateKeyName(encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	prK, puK, err := sync_crypto.GenerateSigningKeys(syncChainSpecs.Seed)
	if err != nil {
		return nil, err
	}

	syncChainSpecs.Client = client
	syncChainSpecs.EncKey = encKey
	syncChainSpecs.HmacKey = hmacKey
	syncChainSpecs.KeyName = keyName
	syncChainSpecs.PrK = prK
	syncChainSpecs.PuK = puK
	syncChainSpecs.Initialized = false

	return syncChainSpecs, nil
}

func (s SyncChainSpecifics) Init() (*sync_pb.ClientToServerResponse, error) {
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

	res, err := s.MakeRequestToServer(msg)

	fmt.Println(s.ServerURL)

	if err != nil {
		return nil, err
	}

	s.Initialized = true

	return res, nil
}

func (s SyncChainSpecifics) GetToken() (string, error) {
	return sync_crypto.GenerateToken(s.PuK, s.PrK, utils.UnixMilli(time.Now()))
}

func (s SyncChainSpecifics) GetSeedHex() string {
	return strings.ToUpper(hex.EncodeToString(s.Seed))
}

func (s SyncChainSpecifics) GetSyncMnemonic() (string, error) {
	return sync_crypto.GetMnemonic(s.Seed)
}

func (s SyncChainSpecifics) MakeRequestToServer(msg *sync_pb.ClientToServerMessage) (*sync_pb.ClientToServerResponse, error) {
	resMessage := &sync_pb.ClientToServerResponse{}
	body, err := proto.Marshal(msg)

	if err != nil {
		return resMessage, err
	}

	req, err := http.NewRequest("POST", s.ServerURL, bytes.NewBuffer(body))
	if err != nil {
		return resMessage, err
	}

	token, err := s.GetToken()
	if err != nil {
		return resMessage, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	res, err := s.Client.Do(req)
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

func (s SyncChainSpecifics) SaveToFile(specsFileName string) error {
	output, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(specsFileName, output, 0644)
}

func (s SyncChainSpecifics) GetSyncQRCode() ([]byte, error) {
	return qrcode.Encode(s.GetSeedHex(), qrcode.Medium, 300)
}

func (s SyncChainSpecifics) SaveSyncQRCodeToFile(qrCodeFileName string) error {
	return qrcode.WriteFile(s.GetSeedHex(), qrcode.Medium, 300, qrCodeFileName)
}

func (s SyncChainSpecifics) SaveSyncMnemonicToFile(mnemonicFileName string) error {
	mnemonic, err := s.GetSyncMnemonic()

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
