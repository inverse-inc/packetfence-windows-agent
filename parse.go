// Go program - Autoconfiguration of wired and wireless networks on windows 7/8/10

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"syscall"

	"encoding/hex"
	"io/ioutil"
	"os/exec"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/nicksnyder/go-i18n/i18n"
	"howett.net/plist"
)

const PROGRAM_NAME = "PacketFence Provisioning Agent"
const VERSION = "1.0.2"

const CERTUTIL_PROGRAM_PATH = "C:\\Windows\\System32\\certutil.exe"
const WIFI_PEAP_TEMPLATE_NAME = "wireless PEAP template"
const WIFI_TLS_TEMPLATE_NAME = "wireless TLS template"
const WIFI_OPEN_TEMPLATE_NAME = "wireless Open template"
const PROFILE_URL = "http://wireless-profiles.packetfence.org/profile.xml"
const EAPTYPE_PEAP = 25
const EAPTYPE_TLS = 13

// French language codes
const SUBLANG_FRENCH = 1036
const SUBLANG_FRENCH_CANADIAN = 3084
const SUBLANG_FRENCH_BELGIAN = 2060
const SUBLANG_FRENCH_LUXEMBOURG = 5132
const SUBLANG_FRENCH_MONACO = 6156
const SUBLANG_FRENCH_SWISS = 4108
const PNG_FILENAME = "pf_bg.png"

var T i18n.TranslateFunc

var windowMsgBox walk.Form

// FilePaths
var TempPATH string
var ProfileDownloaded string
var ProfileTemplated string
var PngFilePath string
var CaFileBinary string
var CertFilePath string

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

// Clean created files
func clean_files() {
	if CertFilePath != "" {
		os.Remove(CertFilePath)
	}
	if CaFileBinary != "" {
		os.Remove(CaFileBinary)
	}
	if PngFilePath != "" {
		os.Remove(PngFilePath)
	}
	if ProfileDownloaded != "" {
		os.Remove(ProfileDownloaded)
	}
	if ProfileTemplated != "" {
		os.Remove(ProfileTemplated)
	}
}

// Exit with error
func exit_1() {
	clean_files()
	os.Exit(1)
}

func main() {
	// Need to add debug
	hideConsole()

	log.Println("==================== PacketFence Provisioning Agent ===================")

	// Set temp directory
	TempPATH = os.Getenv("tmp")
	if TempPATH == "" {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("invalidTempPATH"), walk.MsgBoxOK)
		log.Println("Failed found a temporary directory")
		exit_1()
	}

	// Internationalization (i18n)
	localeInfo := win.GetThreadUILanguage()
	log.Printf("User's locale is: %#x", localeInfo)
	switch localeInfo {
	case SUBLANG_FRENCH, SUBLANG_FRENCH_CANADIAN, SUBLANG_FRENCH_BELGIAN, SUBLANG_FRENCH_LUXEMBOURG, SUBLANG_FRENCH_MONACO, SUBLANG_FRENCH_SWISS:
		languageFileName := "fr.json"
		createLanguageFile(TempPATH, FRENCH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("fr")
	default:
		languageFileName := "en.json"
		createLanguageFile(TempPATH, ENGLISH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("en")
	}

	// PNG
	PngFilePath := TempPATH + "\\"+ PNG_FILENAME
	err := base64ToPng(BACKGROUND_IMAGE_PF, PngFilePath)
	if err != nil {
		exit_1()
	}

	// Windows Box
	walk.Resources.SetRootDirPath(TempPATH)
	var mw1 *walk.MainWindow
	if _, err := (MainWindow{
		AssignTo:   &mw1,
		Title:      fmt.Sprintf("%s - %s", PROGRAM_NAME, VERSION),
		MinSize:    Size{400, 400},
		Layout:     VBox{},
		Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
		Children: []Widget{
			ImageView{
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				Image:      PNG_FILENAME,
			},
			PushButton{
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{50, 50},
				Text:       "Configure",
				OnClicked: func() {
					Configure()
				},
			},
		},
	}.Run()); err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("errorMainWindow"), walk.MsgBoxOK)
		log.Println("Failed opening main window: ", err)
		mw1.Close()
		exit_1()
	}
	clean_files()
	mw1.Close()
	os.Exit(0)
}

func Configure() {
	downloadProfile()
	extractProfile()
}

func downloadProfile(){
	ProfileDownloaded = TempPATH + "\\profile.xml"
	// Download mobileconfig file
	err := writeProfileToLocalFile(ProfileDownloaded, PROFILE_URL)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotRetrieveProfileFile"), walk.MsgBoxOK)
		log.Println("Failed loading profile: ", err)
		exit_1()
	}
	log.Printf("Load Profile from PF")
}

func extractProfile() {
	var xmlPlistProfile map[string]interface{}
	var eapType uint64
	var userCertDecode string
	var wifiIndex int
	var wiredIndex int

	// Read xml profile, convert to string
	data, err := ioutil.ReadFile(ProfileDownloaded)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotReadProfileData"), walk.MsgBoxOK)
		log.Println("Failed reading profile: ", err)
		exit_1()
	}

	// Decode converted xml profile
	dataToString := string(data)
	buffer := bytes.NewReader([]byte(dataToString))
	decoder := plist.NewDecoder(buffer)
	err = decoder.Decode(&xmlPlistProfile)
	if err != nil {
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotDecodeProfileFile"), walk.MsgBoxOK)
		log.Println("Failed decoding profile: ", err)
		exit_1()
	}

	// Get data from the mobileconfig file
	shouldConfigureWifi := false
	shouldConfigureWired := false

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
			CertFilePath = TempPATH+"\\"+userAuth+""+fileExtension
			err := createCertTempFile(CertFilePath, userCert, alertMessage)
			if err != nil {
				log.Println("Failed creating profile: ", err)
				exit_1()
			}
			err = addCertToMachine(userCertDecode, CERTUTIL_PROGRAM_PATH)
			if err != nil {
				log.Println("Failed adding Cert: ", err)
				exit_1()
			}
		// Certificate of Authority configuration
		case "com.apple.security.root":
			if eapType == EAPTYPE_TLS {
				caCert := payloadContent["PayloadContent"].(string)
				caName := payloadContent["PayloadCertificateFileName"].(string)
				fileExtension := ".cer"
				alertMessage := T("cannotGenerateCAFile")
				CaFileBinary = TempPATH+"\\"+caName+""+fileExtension
				err := createCertTempFile(CaFileBinary, caCert, alertMessage)
				if err != nil {
					log.Println("Failed creating profile: ", err)
					exit_1()
				}
				err = addCAToMachine(CaFileBinary, CERTUTIL_PROGRAM_PATH)
				if err != nil {
					log.Println("Failed adding CA: ", err)
					exit_1()
				}
			}
		default:
			walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("Unexpected PayloadType {{.PayloadType}} please contact your local support.", map[string]interface{}{
				"PayloadType": payloadType,
			}), walk.MsgBoxOK)
			log.Println("Unexpected PayloadType: ", payloadType)
			exit_1()
		}
	}

	if shouldConfigureWifi {
		configureWifi(xmlPlistProfile,wifiIndex,eapType)
	}
	if shouldConfigureWired {
		configureWired(xmlPlistProfile,wiredIndex,eapType)
	}
}

func configureWifi(xmlPlistProfile map[string]interface{}, wifiIndex int,eapType uint64){
	var WLAN_ERROR_MESSAGE = T("wlanErrorMessage")
	var templateToFile string
	var elementsToReplaceInTemplate Template
	var wifiKey string

	ProfileTemplated = TempPATH + "\\template-out.xml"

	// Get SSID information
	payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wifiIndex].(map[string]interface{})
	ssidString := payloadContent["SSID_STR"].(string)
	ssidStringToHex := hex.EncodeToString([]byte(ssidString))
	ssidBroadcast := payloadContent["HIDDEN_NETWORK"].(bool)
	securityType := payloadContent["EncryptionType"].(string)
	if securityType == "None" {
		securityType = "open"
	}

	addWLANProfileCommand := exec.Command("netsh", "wlan", "add", "profile", "filename="+ProfileTemplated, "user=all")
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
				log.Println("Failed executing template: ", err)
				exit_1()
			}
			// creates profile file with the executed template
			err = createProfileFile(ProfileTemplated,templateToFile)
			if err != nil {
				log.Println("Failed creating profile file: ", err)
				exit_1()
			}
		}
		if eapType == EAPTYPE_TLS {
			caFingerprint, err := getCAFingerprint(CaFileBinary)
			if err != nil {
				log.Println("Unable to get CA fingerprint: ", err)
				exit_1()
			}
			elementsToReplaceInTemplate = Template{
				ProfileName:     ssidString,
				SsidStringToHex: ssidStringToHex,
				IsSSIDBroadcast: ssidBroadcast,
				SecAuth:         "WPA2",
				Encryption:      "AES",
				CaToTrust:       caFingerprint,
			}
			templateToFile, err = executeTemplate(WIFI_TLS_TEMPLATE_NAME, WIFI_TLS_TEMPLATE, elementsToReplaceInTemplate)
			if err != nil {
				log.Println("Failed executing template: ", err)
				exit_1()
			}
			err = createProfileFile(ProfileTemplated,templateToFile)
			if err != nil {
				log.Println("Failed creating profile file: ", err)
				exit_1()
			}
		}
		if (eapType != EAPTYPE_TLS) && (eapType != EAPTYPE_PEAP) {
			// error handling
			walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("unexpectedEAPType"), walk.MsgBoxOK)
			log.Println("Incorrect EAP type: ", eapType)
			exit_1()
		}
		// adds the new profile to Windows with netsh command
		err := addProfileToMachine(ProfileTemplated, addWLANProfileCommand, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
		if err != nil {
			log.Println("Failed to add profile file: ", err)
			exit_1()
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
		templateToFile, err := executeTemplate(WIFI_OPEN_TEMPLATE_NAME, WIFI_OPEN_TEMPLATE, elementsToReplaceInTemplate)
		if err != nil {
			log.Println("Failed executing template: ", err)
			exit_1()
		}
		err = createProfileFile(ProfileTemplated,templateToFile)
		if err != nil {
			log.Println("Failed creating profile file: ", err)
			exit_1()
		}
		// adds the new profile to Windows with netsh command
		err = addProfileToMachine(ProfileTemplated, addWLANProfileCommand, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
		if err != nil {
			log.Println("Failed to add profile file: ", err)
			exit_1()
		}
	}
}

func configureWired(xmlPlistProfile map[string]interface{}, wiredIndex int,eapType uint64){
	var WIRED_ERROR_MESSAGE = T("wiredErrorMessage")
	var WIRED_SUCCESS_MESSAGE = T("wiredSuccessMessage")

	ProfileTemplated = TempPATH + "\\template-out.xml"
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
	payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wiredIndex].(map[string]interface{})
	eapClientConfiguration := payloadContent["EAPClientConfiguration"].(map[string]interface{})
	eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
	if eapType == EAPTYPE_PEAP {
		err := createProfileFile(ProfileTemplated,WIRED_PEAP_TEMPLATE)
		if err != nil {
			log.Println("Failed creating profile file: ", err)
			exit_1()
		}
	}
	if eapType == EAPTYPE_TLS {
		err := createProfileFile(ProfileTemplated,WIRED_TLS_TEMPLATE)
		if err != nil {
			log.Println("Failed creating profile file: ", err)
			exit_1()
		}
	}
	if (eapType != EAPTYPE_TLS) && (eapType != EAPTYPE_PEAP) {
		// error handling
		walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("unexpectedEAPType"), walk.MsgBoxOK)
		log.Println("Incorrect EAP type: ", eapType)
		exit_1()
	}
	wiredNetshCommand := exec.Command("netsh", "lan", "add", "profile", "filename="+ProfileTemplated)
	err := addProfileToMachine(ProfileTemplated, wiredNetshCommand, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
	if err != nil {
		log.Println("Failed to add profile file: ", err)
		exit_1()
	}
}
