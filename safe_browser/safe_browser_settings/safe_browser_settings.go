package safe_browser_settings

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

//VPNServerConfig holds configuration for integrated VPN
type VPNServerConfig struct {
	Country  string `json:"country"`
	OVPN     string `json:"ovpn"`
	Username string `json:"username"`
	Password string `json:"password"`
}

//SafeBrowserSettings stores safe browser configuration
type SafeBrowserSettings struct {
	//sync server
	SyncServerURL string `json:"syncServerUrl"`
	//auth
	EmployeePassHash []byte `json:"employeePassHash"`
	//URL
	URLAllowlist []string `json:"urlAllowlist"`
	URLBlocklist []string `json:"urlBlocklist"`
	//share
	SharedClipboardEnabled bool `json:"sharedClipboardEnabled"`
	PrintingEnabled        bool `json:"rintingEnabled"`
	//bookmarks
	EditBookmarksEnabled bool     `json:"editBookmarksEnabled"`
	ManagedBookmarks     []string `json:"managedBookmarks"`
	//data
	IncognitoModeAvailability    int  `json:"incognitoModeAvailability"`
	SavingBrowserHistoryDisabled bool `json:"savingBrowserHistoryDisabled"`
	PasswordManagerEnabled       bool `json:"passwordManagerEnabled"`
	//safe search
	ForceGoogleSafeSearch bool `json:"forceGoogleSafeSearch"`
	//YT
	YouTubeRestrictMode int `json:"youTubeRestrictMode"`
	//VPN
	VPNServerConfig *VPNServerConfig
}

//FromFile creates new SafeBrowserConfig struct from json file
func FromFile(fileName string) (*SafeBrowserSettings, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	config := &SafeBrowserSettings{}

	err = json.Unmarshal(byteValue, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

//ToFile saves new SafeBrowserConfig struct to json file
func (s SafeBrowserSettings) ToFile(fileName string) error {
	output, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fileName, output, 0644)
}
