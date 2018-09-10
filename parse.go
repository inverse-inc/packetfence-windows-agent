// Go program - Autoconfiguration of wired and wireless networks on windows 7/8/10

package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"crypto/tls"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"os/exec"
	"text/template"
	"path/filepath"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/nicksnyder/go-i18n/i18n"
	"howett.net/plist"
)

const CERTUTIL_PROGRAM_PATH = "C:\\Windows\\System32\\certutil.exe"
const WIFI_PEAP_TEMPLATE_NAME = "wireless PEAP template"
const WIFI_TLS_TEMPLATE_NAME = "wireless TLS template"
const WIFI_OPEN_TEMPLATE_NAME = "wireless Open template"
const PROFILE_URL = "http://profile.packetfence.org/profile.xml"
const EAPTYPE_PEAP = 25
const EAPTYPE_TLS = 13

// French language codes
const SUBLANG_FRENCH = 1036
const SUBLANG_FRENCH_CANADIAN = 3084
const SUBLANG_FRENCH_BELGIAN = 2060
const SUBLANG_FRENCH_LUXEMBOURG = 5132
const SUBLANG_FRENCH_MONACO = 6156
const SUBLANG_FRENCH_SWISS = 4108

var T i18n.TranslateFunc

var windowMsgBox walk.Form

type Template struct {
	ProfileName     string // replace by SSIDString
	SsidStringToHex string // replace by hex SSIDString
	IsSSIDBroadcast bool   // replace by SSIDBroadcast
	SecAuth         string // replace by securityType, if securityType=None : securityType=open
	OpenPasscode    string // replace by "networkKey"
	WifiKey         string // replace by wifiKey
	Encryption      string // replace by encryption
	CaToTrust       string // replace by sha1 fingerprint
}
type Handle uintptr

func main() {
	log.Println("==================== PacketFence Provisioning Agent ===================")

	currentWorkingDirectory, err := os.Executable()
	if err != nil {
		walk.MsgBox(windowMsgBox, "Error", "Unable to get current working directory, please contact your local support.", walk.MsgBoxOK)
	}
	stableCurrentWorkingDirectory := filepath.Dir(currentWorkingDirectory)

	// Internationalization (i18n)
	localeInfo := win.GetThreadUILanguage()
	log.Printf("User's locale is: %#x", localeInfo)
	switch localeInfo {
	case SUBLANG_FRENCH, SUBLANG_FRENCH_CANADIAN, SUBLANG_FRENCH_BELGIAN, SUBLANG_FRENCH_LUXEMBOURG, SUBLANG_FRENCH_MONACO, SUBLANG_FRENCH_SWISS:
		languageFileName := "fr.json"
		createLanguageFile(stableCurrentWorkingDirectory, FRENCH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("fr")
	default:
		languageFileName := "en.json"
		createLanguageFile(stableCurrentWorkingDirectory, ENGLISH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("en")
	}

	// Main window
	tempPath := os.Getenv("tmp")
	walk.Resources.SetRootDirPath(tempPath)
	_, pfBg := base64ToPng(BACKGROUND_IMAGE_PF, tempPath)
	var mw1 *walk.MainWindow
	if _, err := (MainWindow{
		AssignTo:   &mw1,
		Title:      "PacketFence Provisioning Agent",
		MinSize:    Size{400, 400},
		Layout:     VBox{},
		Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
		Children: []Widget{
			ImageView{
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				Image:      pfBg,
			},
			PushButton{
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{50, 50},
				Text:       "Configure",
				OnClicked: func() {
					Configure()
					mw1.Close()
				},
			},
		},
	}.Run()); err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("errorMainWindow"), walk.MsgBoxOK)
		log.Fatal("Failed opening main window: ", err)
		os.Exit(1)
	}
	os.Remove(tempPath +"\\"+ "pf_bg.png")
	os.Exit(0)
}

func Configure() {
	var WLAN_ERROR_MESSAGE = T("wlanErrorMessage")
	var WIRED_ERROR_MESSAGE = T("wiredErrorMessage")
	var WIRED_SUCCESS_MESSAGE = T("wiredSuccessMessage")
	var xmlPlistProfile map[string]interface{}
	var eapType uint64
	var userCertDecode string
	var templateToFile string
	var elementsToReplaceInTemplate Template
	var wifiKey string
	var caFileBinary string
	var wifiIndex int
	var wiredIndex int
	tempPath := os.Getenv("tmp")
	if tempPath == "" {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("invalidTempPath"), walk.MsgBoxOK)
		os.Exit(1)
	}
	profileFile := tempPath + "\\template-out.xml"

	// Download mobileconfig file
	err := writeProfileToLocalFile("profile.xml", PROFILE_URL)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotRetrieveProfileFile"), walk.MsgBoxOK)
		log.Fatal("Failed loading profile: ", err)
		os.Exit(1)
	}

	// Read xml profile, convert to string
	data, err := ioutil.ReadFile("profile.xml")
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotReadProfileData"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed reading profile: ", err)
	}

	// Decode converted xml profile
	dataToString := string(data)
	buffer := bytes.NewReader([]byte(dataToString))
	decoder := plist.NewDecoder(buffer)
	err = decoder.Decode(&xmlPlistProfile)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotDecodeProfileFile"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed decoding profile: ", err)
	}

	// Get data from the mobileconfig file
	shouldConfigureWifi := false
	shouldConfigureWired := false
	sum := 0

	// Get PayloadContent length
	lengthPayloadContent := len(xmlPlistProfile["PayloadContent"].([]interface{}))

	for i := 0; i < lengthPayloadContent; i++ {
		payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[i].(map[string]interface{})
		payloadType := payloadContent["PayloadType"].(string)

		switch payloadType {
		// Wireless configuration
		case "com.apple.wifi.managed":
			shouldConfigureWifi = true
			// get dict index
			wifiIndex = i
			// Get the EAP type to avoid importing the RADIUS cert as a CA
			eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
			if ok {
				eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
			}
		// Wired configuration
		case "com.apple.firstactiveethernet.managed":
			shouldConfigureWired = true
			wiredIndex = i
			eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
			if ok {
				eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
			}
		// User certificate configuration
		case "com.apple.security.pkcs12":
			userCert := payloadContent["PayloadContent"].(string)
			userAuth := "certificate"
			fileExtension := ".p12"
			alertMessage := T("cannotGenerateCertificateFile")
			userCertDecode, err = createCertTempFile(tempPath, userCert, userAuth, fileExtension, alertMessage)
			err = addCertToMachine(userCertDecode, CERTUTIL_PROGRAM_PATH)
			if err != nil {
				log.Fatal("Failed creating profile: ", err)
				os.Exit(1)
			}
		// Certificate of Authority configuration
		case "com.apple.security.root":
			if eapType == EAPTYPE_TLS {
				caName := payloadContent["PayloadCertificateFileName"].(string)
				caCert := payloadContent["PayloadContent"].(string)
				fileExtension := ".cer"
				alertMessage := T("cannotGenerateCAFile")
				caFileBinary, err = createCertTempFile(tempPath, caCert, caName, fileExtension, alertMessage)
				err = addCAToMachine(caFileBinary, CERTUTIL_PROGRAM_PATH)
				if err != nil {
					log.Fatal("Failed creating profile: ", err)
					os.Exit(1)
				}
			}
		default:
			walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("Unexpected PayloadType {{.PayloadType}} please contact your local support.", map[string]interface{}{
				"PayloadType": payloadType,
				}), walk.MsgBoxOK)
			log.Fatal("Unexpected PayloadType: ", payloadType)
			os.Exit(1)
		}
		sum += i
	}

	if shouldConfigureWifi {
		// Get SSID information
		payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wifiIndex].(map[string]interface{})
		ssidString := payloadContent["SSID_STR"].(string)
		ssidStringToHex := hex.EncodeToString([]byte(ssidString))
		ssidBroadcast := payloadContent["HIDDEN_NETWORK"].(bool)
		securityType := payloadContent["EncryptionType"].(string)
		if securityType == "None" {
			securityType = "open"
		}

		addWLANProfileCommand := exec.Command("netsh", "wlan", "add", "profile", "filename="+profileFile, "user=all")
		wlanSuccessMessage := T("The wireless profile was successfully added to the machine. \nPlease select your newly added profile {{.SsidString}} in the WiFi networks.", map[string]interface{}{
			"SsidString": ssidString,
		})

		// Security of the SSID
		eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
		if ok {
			eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
			userAuth, ok := eapClientConfiguration["UserName"].(string)
			if ok {
				if userAuth == "" {
					userAuth = "certificate"
				}
			} else {
				userAuth = "certificate"
			}
			eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
			if eapType == EAPTYPE_PEAP {
				// Search specific fields in wintemplate and replace them
				elementsToReplaceInTemplate = Template{
					ProfileName:     ssidString,
					SsidStringToHex: ssidStringToHex,
					IsSSIDBroadcast: ssidBroadcast,
					SecAuth:         "WPA2",
					Encryption:      "AES",
				}
				// executes the template
				templateToFile, err := executeTemplate(WIFI_PEAP_TEMPLATE_NAME, WIFI_PEAP_TEMPLATE, elementsToReplaceInTemplate)
				if err != nil {
					log.Fatal("Failed executing template: ", err)
					os.Exit(1)
				}
				// creates profile file with the executed template
				err = createProfileFile(templateToFile)
				if err != nil {
					log.Fatal("Failed creating profile file: ", err)
					os.Exit(1)
				}
				// adds the new profile to Windows with netsh command
				addProfileToMachine(profileFile, addWLANProfileCommand, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
			}
			if eapType == EAPTYPE_TLS {
				caFingerprint, err := getCAFingerprint(caFileBinary)
				if err != nil {
					os.Remove(caFileBinary)
					os.Remove("profile.xml")
					log.Fatal("Unable to get CA fingerprint: ", err)
				}
				elementsToReplaceInTemplate = Template{
					ProfileName:     ssidString,
					SsidStringToHex: ssidStringToHex,
					IsSSIDBroadcast: ssidBroadcast,
					SecAuth:         "WPA2",
					Encryption:      "AES",
					CaToTrust:       caFingerprint,
				}
				os.Remove(caFileBinary)
				templateToFile, err = executeTemplate(WIFI_TLS_TEMPLATE_NAME, WIFI_TLS_TEMPLATE, elementsToReplaceInTemplate)
				if err != nil {
					log.Fatal("Failed executing template: ", err)
					os.Exit(1)
				}
				err = createProfileFile(templateToFile)
				if err != nil {
					log.Fatal("Failed creating profile file: ", err)
					os.Exit(1)
				}
				addProfileToMachine(profileFile, addWLANProfileCommand, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
			}
			if (eapType != EAPTYPE_TLS) && (eapType != EAPTYPE_PEAP) {
				// error handling
				walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("unexpectedEAPType"), walk.MsgBoxOK)
				log.Fatal("Incorrect EAP type: ", eapType)
				os.Exit(1)
			}
		} else {
			wifiKey = payloadContent["Password"].(string)
			log.Println("Security type: ", securityType)
			switch securityType {
			case "WEP":
				elementsToReplaceInTemplate = Template{
					ProfileName:     ssidString,
					SsidStringToHex: ssidStringToHex,
					IsSSIDBroadcast: ssidBroadcast,
					SecAuth:         "open",
					OpenPasscode:    "passPhrase",
					WifiKey:         wifiKey,
					Encryption:      "WEP",
				}
			case "WPA":
				elementsToReplaceInTemplate = Template{
					ProfileName:     ssidString,
					SsidStringToHex: ssidStringToHex,
					IsSSIDBroadcast: ssidBroadcast,
					SecAuth:         "WPA2PSK",
					OpenPasscode:    "passPhrase",
					WifiKey:         wifiKey,
					Encryption:      "AES",
				}
			default:
				elementsToReplaceInTemplate = Template{
					ProfileName:     ssidString,
					SsidStringToHex: ssidStringToHex,
					IsSSIDBroadcast: ssidBroadcast,
					SecAuth:         "open",
					OpenPasscode:    "passPhrase",
					WifiKey:         wifiKey,
					Encryption:      "none",
				}
			}
			templateToFile, err = executeTemplate(WIFI_OPEN_TEMPLATE_NAME, WIFI_OPEN_TEMPLATE, elementsToReplaceInTemplate)
			if err != nil {
				log.Fatal("Failed executing template: ", err)
				os.Exit(1)
			}
			err = createProfileFile(templateToFile)
			if err != nil {
				log.Fatal("Failed creating profile file: ", err)
				os.Exit(1)
			}
			addProfileToMachine(profileFile, addWLANProfileCommand, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
		}
	}
	if shouldConfigureWired {
		dot3svc := exec.Command("net", "start", "dot3svc")
		dot3svc.Start()
		if err := dot3svc.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					exitStatus := status.ExitStatus()
					if exitStatus != 2 {
						walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("dot3svcFail"), walk.MsgBoxOK)
						log.Print("The Wired Autoconfig service could not be started.", err)
					}
				}
			}
		}
		wiredNetshCommand := exec.Command("netsh", "lan", "add", "profile", "filename="+profileFile)
		payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wiredIndex].(map[string]interface{})
		eapClientConfiguration := payloadContent["EAPClientConfiguration"].(map[string]interface{})
		eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
		if eapType == EAPTYPE_PEAP {
			err = createProfileFile(WIRED_PEAP_TEMPLATE)
			addProfileToMachine(profileFile, wiredNetshCommand, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
			if err != nil {
				log.Fatal("Failed creating profile file: ", err)
				os.Exit(1)
			}
		}
		if eapType == EAPTYPE_TLS {
			err = createProfileFile(WIRED_TLS_TEMPLATE)
			addProfileToMachine(profileFile, wiredNetshCommand, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
			if err != nil {
				log.Fatal("Failed creating profile file: ", err)
				os.Exit(1)
			}
		}
		if (eapType != EAPTYPE_TLS) && (eapType != EAPTYPE_PEAP) {
			// error handling
			walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("unexpectedEAPType"), walk.MsgBoxOK)
			log.Fatal("Incorrect EAP type: ", eapType)
			os.Exit(1)
		}
	}
}

// Get mobileconfig file and write to local file
func writeProfileToLocalFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	// Avoid certificate check
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: tr}
	// Get the data
	resp, err := cli.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

// Create, parse and execute templates
func executeTemplate(nameTemplate, constTemplate string, templateToApply Template) (string, error) {
	newTemplate := template.New(nameTemplate)
	// parses template
	newTemplate, err := newTemplate.Parse(constTemplate)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotParseTemplate"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed parsing: ", err)
		return "", err
	}
	// executes the template into the open file
	var templateBuffer bytes.Buffer
	err = newTemplate.Execute(&templateBuffer, templateToApply)
	if err != nil {
		log.Println("Error:  ", err)
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotExecuteTemplate"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed executing: ", err)
		return templateBuffer.String(), err
	}
	// handles error
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotCreateWLANProfile"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed creating WLANProfile: ", err)
		return templateBuffer.String(), err
	}
	return templateBuffer.String(), nil
}

// Create and write profile file into templateToFile folder
func createProfileFile(templateToFile string) error {
	tempPath := os.Getenv("tmp")
	// create and open file
	profileFilePath := tempPath + "\\" + "template-out.xml"
	profileFile, err := os.Create(profileFilePath)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotCreateProfileFile"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		log.Fatal("Failed creating profile file: ", err)
		return err
	}
	// close file
	defer profileFile.Close()
	// write the template into the new file
	_, err = io.Copy(profileFile, strings.NewReader(templateToFile))
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotWriteIntoProfileFile"), walk.MsgBoxOK)
		os.Remove("profile.xml")
		os.Remove(profileFilePath)
		log.Fatal("Failed writing template to file: ", err)
		return err
	}
	os.Remove("profile.xml")
	log.Println("Information:", T("profileCreationSuccess"))
	return nil
}

// Add wired and wireless profiles to Windows
func addProfileToMachine(profileFile string, cmd *exec.Cmd, ErrorMessage, SuccessMessage string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed adding profile: output: %s\n", output, err)
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), ErrorMessage, walk.MsgBoxOK)
		os.Remove(profileFile)
		log.Fatal("Failed adding profile: ", err, output)
		return err
	} else {
		walk.MsgBox(windowMsgBox, "Information:", SuccessMessage, walk.MsgBoxOK)
		os.Remove(profileFile)
	}
	return nil
}
