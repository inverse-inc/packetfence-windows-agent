// Go program - Autoconfiguration of wired and wireless networks on windows 7/8/10

package main

import (
	"bytes"
	"fmt"
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
	"path/filepath"
	"text/template"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/nicksnyder/go-i18n/i18n"
	"howett.net/plist"
)

const PROGRAM_NAME = "PacketFence Provisioning Agent"
const VERSION = "1.0.1"

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

var debug = false
var mw1 *walk.MainWindow
var configButton, debugButton, closedButton *walk.PushButton
var imgView *walk.ImageView
var debugTxt *walk.TextEdit
var debugGrpBox *walk.GroupBox
var cafilePath string

var tempPath string
var pngFileName string
var pngFilePath string
var userCertPath string
var profilePath string
var stableCurrentWorkingDirectory string

func main() {
	hideConsole()
	prepareMainWindow()
	if err := (MainWindow{
		AssignTo:   &mw1,
		Title:      fmt.Sprintf("%s - %s", PROGRAM_NAME, VERSION),
		MinSize:    Size{500, 400},
		Layout:     VBox{},
		Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
		Children: []Widget{
			ImageView{
				AssignTo:   &imgView,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				//Image:      pngFileName,
				Visible: true,
			},
			GroupBox{
				Title:    "Configuration Debug output",
				AssignTo: &debugGrpBox,
				Visible:  false,
				Layout:   VBox{},
				Children: []Widget{
					ScrollView{
						HorizontalFixed: true,
						Layout:          VBox{},
						Children: []Widget{
							TextEdit{
								MinSize:  Size{400, 10},
								AssignTo: &debugTxt,
								ReadOnly: false,
								Text:     "",
							},
						},
					},
				},
			},
			PushButton{
				AssignTo:   &configButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{50, 50},
				Text:       "Configure",
				OnClicked: func() {
					fetchPortalDomainName()
				},
			},
			PushButton{
				AssignTo:   &debugButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{10, 10},
				Text:       "Debug",
				OnClicked: func() {
					viewDebug()
				},
			},
			PushButton{
				AssignTo:   &closedButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{10, 10},
				Text:       "Close",
				Visible:    false,
				OnClicked: func() {
					cleanAndExit()
					mw1.Close()
				},
			},
		},
		OnSizeChanged: func() {
			mw1size := Size{500, 400}
			mw1.SetSize(walk.Size(mw1size))
		},
	}.Create()); err != nil {
		log.Print("Failed opening main window: ", err)
		viewErrorAndExit(T("errorMainWindow: " + err.Error()))
	}
	prepareEnv()
	prepareBackgroundImage()

	mw1.Run()
}

func prepareMainWindow() {
	currentWorkingDirectory, err := os.Executable()
	if err != nil {
		walk.MsgBox(windowMsgBox, "Error", "Unable to get current working directory, please contact your local support.", walk.MsgBoxOK)
	}
	stableCurrentWorkingDirectory = filepath.Dir(currentWorkingDirectory)
	tempPath = os.Getenv("tmp")
	// Access to tmp path
	if tempPath == "" {
		viewErrorAndExit(T("invalidTempPath"))
	}
	walk.Resources.SetRootDirPath(tempPath)
}

func prepareEnv() {
	debug = true
	addNewLinesToDebug("============== PacketFence Provisioning Agent ==============")

	// Internationalization (i18n)
	localeInfo := win.GetThreadUILanguage()
	addNewLinesToDebug("User's locale uint16 is: " + fmt.Sprintf("%v", localeInfo))
	switch localeInfo {
	case SUBLANG_FRENCH, SUBLANG_FRENCH_CANADIAN, SUBLANG_FRENCH_BELGIAN, SUBLANG_FRENCH_LUXEMBOURG, SUBLANG_FRENCH_MONACO, SUBLANG_FRENCH_SWISS:
		languageFileName := "fr.json"
		createLanguageFile(stableCurrentWorkingDirectory, FRENCH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("fr")
		addNewLinesToDebug("Program will be translated in french.")
	default:
		languageFileName := "en.json"
		createLanguageFile(stableCurrentWorkingDirectory, ENGLISH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("en")
		addNewLinesToDebug("Program will be translated in english.")
	}

	pngFileName = "pf_bg.png"
	pngFilePath = tempPath + "\\" + pngFileName
	userCertPath = ""
	profilePath = tempPath + "\\template-out.xml"
	debug = false
}

func fetchPortalDomainName() {
	var xmlPlistProfile map[string]interface{}

	// Download mobileconfig file
	err := writeProfileToLocalFile("profile.xml", PROFILE_URL)
	if err != nil {
		addNewLinesToDebug("Failed loading profile: " + err.Error())
		viewErrorAndExit(T("cannotRetrieveProfileFile"))
	} else {
		// Read xml profile, convert to string
		data, err := ioutil.ReadFile("profile.xml")
		if err != nil {
			addNewLinesToDebug("Failed reading profile: " + err.Error())
			viewErrorAndExit(T("cannotReadProfileData"))
		} else {
			// Decode converted xml profile
			dataToString := string(data)
			buffer := bytes.NewReader([]byte(dataToString))
			decoder := plist.NewDecoder(buffer)
			err = decoder.Decode(&xmlPlistProfile)
			if err != nil {
				addNewLinesToDebug("Failed decoding profile: " + err.Error())
				viewErrorAndExit(T("cannotDecodeProfileFile"))
			} else {
				fetchXML()
			}
		}
	}
}

func fetchXML() {
	var xmlPlistProfile map[string]interface{}
	var wifiIndex int
	var wiredIndex int
	var eapType uint64
	var userCertDecode string
	var caFileBinary string
	var err error

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
				addNewLinesToDebug("Extract Wireless configuration profile.")
			} else {
				addNewLinesToDebug("Failed Extract Wirless configuration profile")
				viewErrorAndExit("Failed Extract Wireless configuration profile")
			}
		// Wired configuration
		case "com.apple.firstactiveethernet.managed":
			shouldConfigureWired = true
			wiredIndex = i
			eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
			if ok {
				eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
				addNewLinesToDebug("Extract Wired configuration profile.")
			} else {
				addNewLinesToDebug("Failed Extract Wired configuration profile")
				viewErrorAndExit("Failed Extract Wired configuration profile")
			}
		// User certificate configuration
		case "com.apple.security.pkcs12":
			userCert := payloadContent["PayloadContent"].(string)
			userCertPath = tempPath + "\\" + "certificate.p12"
			err = createCertTempFile(userCert, userCertPath)
			if err != nil {
				addNewLinesToDebug("Failed Generating User Certificate : " + err.Error())
				viewErrorAndExit(T("cannotGenerateCertificateFile"))
			} else {
				err = addCertToMachine(userCertDecode, CERTUTIL_PROGRAM_PATH)
				if err != nil {
					addNewLinesToDebug("Failed creating profile: " + err.Error())
					viewErrorAndExit(T("cannotDecodeProfileFile"))
				}
			}
		// Certificate of Authority configuration
		case "com.apple.security.root":
			if eapType == EAPTYPE_TLS {
				caName := payloadContent["PayloadCertificateFileName"].(string)
				caCert := payloadContent["PayloadContent"].(string)
				cafilePath = tempPath + "\\" + caName + ".cer"
				err = createCertTempFile(caCert, cafilePath)
				if err != nil {
					addNewLinesToDebug("Failed Generating CA Certificate : " + err.Error())
					viewErrorAndExit(T("cannotGenerateCAFile"))
				}
				err = addCAToMachine(caFileBinary, CERTUTIL_PROGRAM_PATH)
				if err != nil {
					addNewLinesToDebug("Failed creating profile: " + err.Error())
					viewErrorAndExit(T("cannotDecodeProfileFile"))
				}
			}
		default:
			addNewLinesToDebug(T("Unexpected PayloadType: ", map[string]interface{}{
				"PayloadType": payloadType,
			}))
			viewErrorAndExit(T("Unexpected PayloadType."))
		}
		sum += i
	}
	if shouldConfigureWifi {
		configureWifi(xmlPlistProfile, wifiIndex, eapType, caFileBinary)
	}
	if shouldConfigureWired {
		configureWired(xmlPlistProfile, wiredIndex, eapType)
	}
}

// Configure wifi
func configureWifi(xmlPlistProfile map[string]interface{}, wifiIndex int, eapType uint64, caFileBinary string) {
	var WLAN_ERROR_MESSAGE = T("wlanErrorMessage")
	var templateToFile string
	var elementsToReplaceInTemplate Template
	var wifiKey string
	var err error
	// Get SSID information
	payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wifiIndex].(map[string]interface{})
	ssidString := payloadContent["SSID_STR"].(string)
	ssidStringToHex := hex.EncodeToString([]byte(ssidString))
	ssidBroadcast := payloadContent["HIDDEN_NETWORK"].(bool)
	securityType := payloadContent["EncryptionType"].(string)
	if securityType == "None" {
		securityType = "open"
	}

	wlanCmd := exec.Command("netsh", "wlan", "add", "profile", "filename="+profilePath, "user=all")
	wlanCmdOutput := &bytes.Buffer{}
	wlanCmd.Stdout = wlanCmdOutput
	wlanCmdErr := wlanCmd.Run()
	if wlanCmdErr != nil {
		// There is an issue with the command line
		addNewLinesToDebug(T("==> Executing: %s\n", strings.Join(wlanCmd.Args, " ")))
		addNewLinesToDebug(T("==> Error: %s\n", wlanCmdErr.Error()))
		addNewLinesToDebug(T("==> Ouput: %s\n", string(wlanCmdOutput.Bytes())))
	}

	wlanSuccessMessage := T("The wireless profile was successfully added to the machine. \nPlease select your newly added profile " + ssidString + " in the WiFi networks.")

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
				addNewLinesToDebug("Failed executing template: " + err.Error())
				viewErrorAndExit(T("Unexpected Error when executing the template."))
			}
			// creates profile file with the executed template
			err = createProfileFile(templateToFile)
			if err != nil {
				addNewLinesToDebug("Failed creating profile file: " + err.Error())
				viewErrorAndExit(T("Unexpected Error when creating profile file."))
			}
			// adds the new profile to Windows with netsh command
			addProfileToMachine(profilePath, wlanCmd, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
		} else if eapType == EAPTYPE_TLS {
			caFingerprint, err := getCAFingerprint(caFileBinary)
			if err != nil {
				addNewLinesToDebug("Unable to get CA fingerprint: " + err.Error())
				viewErrorAndExit(T("Unable to get CA fingerprint."))
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
				addNewLinesToDebug("Failed executing template: " + err.Error())
				viewErrorAndExit(T("Failed executing template."))
			}
			err = createProfileFile(templateToFile)
			if err != nil {
				addNewLinesToDebug("Failed creating profile file: " + err.Error())
				viewErrorAndExit(T("Failed creating profile file."))
			}
			addProfileToMachine(profilePath, wlanCmd, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
		} else {
			// error handling
			addNewLinesToDebug(T("unexpectedEAPType") + fmt.Sprintf("%v", eapType))
			viewErrorAndExit(T("unexpectedEAPType"))
		}
		addNewLinesToDebug("EAPType is " + fmt.Sprintf("%v", eapType))
	} else {
		wifiKey = payloadContent["Password"].(string)
		addNewLinesToDebug("Security type: " + securityType)
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
			addNewLinesToDebug("Failed executing template: " + err.Error())
			viewErrorAndExit("Failed executing template.")
		} else {
			err = createProfileFile(templateToFile)
			if err != nil {
				addNewLinesToDebug("Failed creating template: " + err.Error())
				viewErrorAndExit("Failed creating template.")
			} else {
				addProfileToMachine(profilePath, wlanCmd, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
			}
		}
	}
}

// Configuration for wired
func configureWired(xmlPlistProfile map[string]interface{}, wiredIndex int, eapType uint64) {
	var WIRED_ERROR_MESSAGE = T("wiredErrorMessage")
	var WIRED_SUCCESS_MESSAGE = T("wiredSuccessMessage")
	var err error

	dot3svc := exec.Command("net", "start", "dot3svc")
	dot3svc.Start()
	if err := dot3svc.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitStatus := status.ExitStatus()
				if exitStatus != 2 {
					addNewLinesToDebug("The Wired Autoconfig service could not be started due to: " + err.Error())
					viewErrorAndExit(T("dot3svcFail"))
				} else {
					addNewLinesToDebug("The Wired Autoconfig service has been started")
				}
			}
		}
	}
	wiredNetshCommand := exec.Command("netsh", "lan", "add", "profile", "filename="+profilePath)
	payloadContent := xmlPlistProfile["PayloadContent"].([]interface{})[wiredIndex].(map[string]interface{})
	eapClientConfiguration := payloadContent["EAPClientConfiguration"].(map[string]interface{})
	eapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
	if eapType == EAPTYPE_PEAP {
		err = createProfileFile(WIRED_PEAP_TEMPLATE)
		addProfileToMachine(profilePath, wiredNetshCommand, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
		if err != nil {
			addNewLinesToDebug("Failed creating profile file: " + err.Error())
			viewErrorAndExit("Failed creating profile file.")
		} else {
			addNewLinesToDebug("Success creating profile file: " + err.Error())
		}
	} else if eapType == EAPTYPE_TLS {
		err = createProfileFile(WIRED_TLS_TEMPLATE)
		addProfileToMachine(profilePath, wiredNetshCommand, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
		if err != nil {
			addNewLinesToDebug("Failed creating profile file: " + err.Error())
			viewErrorAndExit("Failed creating profile file.")
		} else {
			addNewLinesToDebug("Success creating profile file: " + err.Error())
		}
	} else {
		// error handling
		addNewLinesToDebug(T("unexpectedEAPType") + err.Error())
		viewErrorAndExit(T("unexpectedEAPType"))
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
	var templateBuffer bytes.Buffer
	// parses template
	newTemplate, err := newTemplate.Parse(constTemplate)
	if err != nil {
		addNewLinesToDebug(T("cannotParseTemplate") + err.Error())
		viewErrorAndExit(T("cannotParseTemplate"))
	} else {
		// executes the template into the open file
		err = newTemplate.Execute(&templateBuffer, templateToApply)
		if err != nil {
			addNewLinesToDebug(T("cannotExecuteTemplate") + err.Error())
			viewErrorAndExit(T("cannotExecuteTemplate"))
			return "", err
		}
		return templateBuffer.String(), err
	}
	return "", nil
}

// Create and write profile file into templateToFile folder
func createProfileFile(templateToFile string) error {
	// create and open file
	profileFile, err := os.Create(profilePath)
	if err != nil {
		addNewLinesToDebug(T("cannotCreateProfileFile") + err.Error())
		viewErrorAndExit(T("cannotCreateProfileFile"))
		return err
	} else {
		// close file
		defer profileFile.Close()
		// write the template into the new file
		_, err = io.Copy(profileFile, strings.NewReader(templateToFile))
		if err != nil {
			addNewLinesToDebug(T("cannotWriteIntoProfileFile") + err.Error())
			viewErrorAndExit(T("cannotWriteIntoProfileFile"))
			return err
		}
	}
	addNewLinesToDebug(T("profileCreationSuccess") + err.Error())
	return nil
}

// Add wired and wireless profiles to Windows
func addProfileToMachine(profileFile string, cmd *exec.Cmd, ErrorMessage, SuccessMessage string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		addNewLinesToDebug("Failed adding profile" + ErrorMessage + err.Error() + fmt.Sprintf("%v", output))
		viewErrorAndExit("Failed adding profile")
		return err
	} else {
		addNewLinesToDebug("Failed adding profile" + SuccessMessage)
		return nil
	}
}
