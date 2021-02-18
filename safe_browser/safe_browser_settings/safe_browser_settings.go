package safe_browser_settings

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

//SafeBrowserSettings stores safe browser configuration
type SafeBrowserSettings struct {
	SyncServerURL    string   `json:"syncServerUrl"`
	EmployeePassHash []byte   `json:"employeePassHash"`
	URLAllowlist     []string `json:"urlAllowlist"`
	URLBlocklist     []string `json:"urlBlocklist"`
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
