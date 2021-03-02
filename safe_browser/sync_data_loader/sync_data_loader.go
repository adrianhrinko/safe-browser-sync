package main

import (
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/brave/go-sync/safe_browser/safe_browser_settings"
	sync_chain_specs "github.com/brave/go-sync/safe_browser/sync_chain_specifics"
	"github.com/brave/go-sync/safe_browser/sync_crypto"
	"github.com/brave/go-sync/schema/protobuf/sync_pb"
	"github.com/brave/go-sync/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
)

const (
	//sync type
	bookmarkType int32 = 32904
	prefsType    int32 = 37702
	nigoriType   int32 = 47745
	devInfoType  int32 = 154522
	sessionType  int32 = 50119

	//pref names
	passwordHashPrefName              string = "safe_browser.password_hash"
	vpnConfigPrefName                 string = "safe_browser.vpn_config"
	URLBlockListPrefName              string = "policy.url_blacklist"
	URLAllowListPrefName              string = "policy.url_whitelist"
	sharedClipboardPrefName           string = "browser.shared_clipboard_enabled"
	printingPrefName                  string = "printing.enabled"
	editBookmarksPrefName             string = "bookmarks.editing_enabled"
	managedBookmarksPrefName          string = "bookmarks.managed_bookmarks"
	incognitoModeAvailabilityPrefName string = "incognito.mode_availability"
	savingBrowserHistoryPrefName      string = "history.saving_disabled"
	passwordManagerPrefName           string = "credentials_enable_service"
	GoogleSafeSearchPrefName          string = "settings.force_google_safesearch"
	YouTubeRestrictModePrefName       string = "settings.force_youtube_restrict"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

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

func getClientToServerCommitMsg(entries []*sync_pb.SyncEntity, cacheGUID *string) *sync_pb.ClientToServerMessage {
	commitMsg := &sync_pb.CommitMessage{
		Entries:   entries,
		CacheGuid: cacheGUID,
	}
	commit := sync_pb.ClientToServerMessage_COMMIT
	return &sync_pb.ClientToServerMessage{
		MessageContents: &commit,
		Commit:          commitMsg,
		Share:           aws.String("?"),
	}
}

func getEncryptedData(msg []byte, syncSpecs *sync_chain_specs.SyncChainSpecifics) (*sync_pb.EncryptedData, error) {

	encryptedData := &sync_pb.EncryptedData{}

	encrypted, err := sync_crypto.AESCBCEncrypt(syncSpecs.EncKey, msg, syncSpecs.HmacKey)
	if err != nil {
		return encryptedData, err
	}

	encoded := b64.StdEncoding.EncodeToString(encrypted)

	encryptedData.KeyName = aws.String(syncSpecs.KeyName)
	encryptedData.Blob = aws.String(encoded)

	return encryptedData, nil
}

func updateNigoriWithEncryptionData(syncSpecs *sync_chain_specs.SyncChainSpecifics) (*sync_pb.ClientToServerResponse, error) {
	resMessage := &sync_pb.ClientToServerResponse{}

	zeroez := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	marker := getMarker([]int64{0}, []int32{nigoriType})
	msg := getClientToServerGUMsg(marker, sync_pb.SyncEnums_GU_TRIGGER, true, nil)
	response, err := syncSpecs.MakeRequestToServer(msg)
	if err != nil {
		return resMessage, err
	}

	nigoriEntry := response.GetUpdates.Entries[0]

	nigori := nigoriEntry.Specifics.GetNigori()

	keyBag := &sync_pb.NigoriKeyBag{
		Key: []*sync_pb.NigoriKey{
			{
				DeprecatedName:    aws.String(syncSpecs.KeyName),
				DeprecatedUserKey: zeroez,
				EncryptionKey:     syncSpecs.EncKey,
				MacKey:            syncSpecs.HmacKey,
			},
		},
	}

	encryptionKeybag, err := proto.Marshal(keyBag)
	if err != nil {
		return resMessage, err
	}
	encryptedData, err := getEncryptedData(encryptionKeybag, syncSpecs)
	if err != nil {
		return resMessage, err
	}

	nigori.EncryptionKeybag = encryptedData
	nigori.CustomPassphraseKeyDerivationSalt = aws.String(b64.StdEncoding.EncodeToString(syncSpecs.Salt))
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

	msg = getClientToServerCommitMsg(entries, nil)

	resMessage, err = syncSpecs.MakeRequestToServer(msg)

	return resMessage, nil
}

func prepareSyncEntity(specifics *sync_pb.EntitySpecifics) (*sync_pb.SyncEntity, error) {
	entity := &sync_pb.SyncEntity{}

	clientItemID, err := uuid.NewRandom()
	if err != nil {
		return entity, err
	}

	uniqueTag := sync_crypto.GenRandomBytes(20)

	entity.Version = aws.Int64(0)
	entity.Name = aws.String("encrypted")
	entity.Deleted = aws.Bool(false)
	entity.IdString = aws.String(clientItemID.String())
	entity.Folder = aws.Bool(false)
	entity.ClientDefinedUniqueTag = aws.String(b64.StdEncoding.EncodeToString(uniqueTag))
	entity.Ctime = aws.Int64(utils.GetCTime())
	entity.Mtime = entity.Ctime
	entity.Specifics = specifics

	return entity, nil
}

func preparePrefsEntity(prefName string, pref interface{},
	syncSpecs *sync_chain_specs.SyncChainSpecifics) (*sync_pb.SyncEntity, error) {

	prefs := &sync_pb.PreferenceSpecifics{}

	prefJSON, err := json.Marshal(pref)
	if err != nil {
		return nil, err
	}

	prefs.Name = aws.String(prefName)
	prefs.Value = aws.String(string(prefJSON))

	prefSpecs := &sync_pb.EntitySpecifics{
		SpecificsVariant: &sync_pb.EntitySpecifics_Preference{
			Preference: prefs,
		},
	}

	bytes, err := proto.Marshal(prefSpecs)
	if err != nil {
		return nil, err
	}

	encryptedData, err := getEncryptedData(bytes, syncSpecs)
	if err != nil {
		return nil, err
	}

	specifics := &sync_pb.EntitySpecifics{
		Encrypted: encryptedData,
		SpecificsVariant: &sync_pb.EntitySpecifics_Preference{
			Preference: &sync_pb.PreferenceSpecifics{},
		},
	}

	return prepareSyncEntity(specifics)
}

func loadSettings(settings *safe_browser_settings.SafeBrowserSettings,
	syncSpecs *sync_chain_specs.SyncChainSpecifics) (*sync_pb.ClientToServerResponse, error) {

	passEntity, err := preparePrefsEntity(passwordHashPrefName, settings.EmployeePassHash, syncSpecs)
	urlBlocklistEntity, err := preparePrefsEntity(URLBlockListPrefName, settings.URLBlocklist, syncSpecs)
	urlAllowlistEntity, err := preparePrefsEntity(URLAllowListPrefName, settings.URLAllowlist, syncSpecs)
	sharedClipboardEntity, err := preparePrefsEntity(sharedClipboardPrefName, settings.SharedClipboardEnabled, syncSpecs)
	printingEntity, err := preparePrefsEntity(printingPrefName, settings.PrintingEnabled, syncSpecs)
	passwordManagerEntity, err := preparePrefsEntity(passwordManagerPrefName, settings.PasswordManagerEnabled, syncSpecs)
	googleSearchEntity, err := preparePrefsEntity(GoogleSafeSearchPrefName, settings.ForceGoogleSafeSearch, syncSpecs)
	browserHistoryEntity, err := preparePrefsEntity(savingBrowserHistoryPrefName, settings.SavingBrowserHistoryDisabled, syncSpecs)
	editBookmarksEntity, err := preparePrefsEntity(editBookmarksPrefName, settings.EditBookmarksEnabled, syncSpecs)
	vpnConfigEntity, err := preparePrefsEntity(vpnConfigPrefName, settings.VPNServerConfig, syncSpecs)
	//managedBookmarksEntity, err := preparePrefsEntity(managedBookmarksPrefName, settings.ManagedBookmarks, syncSpecs)

	if err != nil {
		return nil, err
	}

	entries := []*sync_pb.SyncEntity{
		passEntity,
		urlBlocklistEntity,
		urlAllowlistEntity,
		sharedClipboardEntity,
		printingEntity,
		passwordManagerEntity,
		googleSearchEntity,
		browserHistoryEntity,
		editBookmarksEntity,
		vpnConfigEntity,
	}

	msg := getClientToServerCommitMsg(entries, aws.String(syncSpecs.CacheGUID))

	fmt.Println(proto.MarshalTextString(msg))

	return syncSpecs.MakeRequestToServer(msg)
}

func createAndInitSpecs(syncServerURL string) *sync_chain_specs.SyncChainSpecifics {
	syncSpecs, err := sync_chain_specs.New(&http.Client{}, syncServerURL)
	check(err)
	_, err = syncSpecs.Init()
	check(err)

	return syncSpecs
}

func saveDataOnDisc(syncSpecs *sync_chain_specs.SyncChainSpecifics) {
	err := syncSpecs.SaveToFile("sync_specs.json")
	check(err)
	err = syncSpecs.SaveSyncMnemonicToFile("mnemonic.txt")
	check(err)
	err = syncSpecs.SaveSyncQRCodeToFile("qr.png")
	check(err)
}

func getPassHash(password string) ([]byte, error) {

	salt := sync_crypto.GenRandomBytes(32)
	hash, err := sync_crypto.Scrypt([]byte(password), salt)
	if err != nil {
		return nil, err
	}

	passHash := append(hash, salt...)

	return passHash, nil
}

func createSyncData(settings *safe_browser_settings.SafeBrowserSettings) {
	syncSpecs := createAndInitSpecs(settings.SyncServerURL)

	saveDataOnDisc(syncSpecs)

	_, err := updateNigoriWithEncryptionData(syncSpecs)
	check(err)

	_, err = loadSettings(settings, syncSpecs)
	check(err)
}

func loadVPNCertFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return b64.StdEncoding.EncodeToString(byteValue), nil

}

func main() {

	password := "password"

	passHash, err := getPassHash(password)
	check(err)

	vpnCert, err := loadVPNCertFile("../assets/test_vpn.ovpn")
	check(err)

	settings := &safe_browser_settings.SafeBrowserSettings{
		SyncServerURL:    "http://localhost:8295/sync/command/",
		EmployeePassHash: passHash,
		URLBlocklist: []string{
			"https://stackoverflow.com/",
			"https://www.fi.muni.cz/",
		},
		URLAllowlist:                 []string{},
		SharedClipboardEnabled:       false,
		PrintingEnabled:              false,
		PasswordManagerEnabled:       false,
		ForceGoogleSafeSearch:        true,
		SavingBrowserHistoryDisabled: true,
		ManagedBookmarks: []string{
			"https://www.office.com/",
			"https://www.microsoft.com/en-us/microsoft-365/onedrive/online-cloud-storage",
		},
		EditBookmarksEnabled: false,
		VPNServerConfig: &safe_browser_settings.VPNServerConfig{
			OVPN:     vpnCert,
			Country:  "Korea",
			Username: "vpn",
			Password: "vpn",
		},
	}

	createSyncData(settings)
}
