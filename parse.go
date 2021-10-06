// Go program - Autoconfiguration of wired and wireless networks on windows 7/8/10

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"encoding/hex"
	"io/ioutil"
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

type WinAgentWindow struct {
	ClosedButton *walk.PushButton
	ConfigButton *walk.PushButton
	DebugButton  *walk.PushButton
	DebugGrpBox  *walk.GroupBox
	DebugTxt     *walk.TextEdit
	ImgView      *walk.ImageView
	Mw1          *walk.MainWindow
}

type WinAgent struct {
	CaCert                        string
	CaFileBinary                  string
	CaFilePath                    string
	CaName                        string
	Debug                         bool
	EapType                       uint64
	Err                           error
	PngFileName                   string
	PngFilePath                   string
	ProfilePath                   string
	StableCurrentWorkingDirectory string
	WlanCmd                       *exec.Cmd
	WiredCmd                      *exec.Cmd
	TemplateOutPath               string
	TempPath                      string
	UserCert                      string
	UserCertDecode                string
	UserCertPath                  string
	WifiIndex                     int
	Window                        *WinAgentWindow
	WiredIndex                    int
	XmlPlistProfile               map[string]interface{}
}

var winAgentWindow *WinAgentWindow
var wi *WinAgent

func main() {
	hideConsole()
	prepareMainWindow()
	if err := (MainWindow{
		AssignTo:   &wi.Window.Mw1,
		Title:      fmt.Sprintf("%s - %s", PROGRAM_NAME, VERSION),
		MinSize:    Size{Width: 500, Height: 400},
		Layout:     VBox{},
		Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
		Children: []Widget{
			ImageView{
				AssignTo:   &wi.Window.ImgView,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				//Image:      pngFileName,
				Visible: true,
			},
			GroupBox{
				Title:    "Configuration Debug output",
				AssignTo: &wi.Window.DebugGrpBox,
				Visible:  false,
				Layout:   VBox{},
				Children: []Widget{
					ScrollView{
						HorizontalFixed: true,
						Layout:          VBox{},
						Children: []Widget{
							TextEdit{
								MinSize:  Size{Width: 400, Height: 10},
								AssignTo: &wi.Window.DebugTxt,
								ReadOnly: false,
								Text:     "",
							},
						},
					},
				},
			},
			PushButton{
				AssignTo:   &wi.Window.ConfigButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{Width: 50, Height: 50},
				Text:       "Configure",
				OnClicked: func() {
					fetchPortalDomainName()
				},
			},
			PushButton{
				AssignTo:   &wi.Window.DebugButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{Width: 10, Height: 10},
				Text:       "Debug",
				OnClicked: func() {
					viewDebug()
				},
			},
			PushButton{
				AssignTo:   &wi.Window.ClosedButton,
				Background: SolidColorBrush{Color: walk.RGB(4, 5, 3)},
				MinSize:    Size{Width: 10, Height: 10},
				Text:       "Close",
				Visible:    false,
				OnClicked: func() {
					cleanAndExit(0)
				},
			},
		},
		OnSizeChanged: func() {
			mw1size := Size{Width: 500, Height: 400}
			wi.Window.Mw1.SetSize(walk.Size(mw1size))
		},
	}.Create()); err != nil {
		log.Print("Failed opening main window: ", err.Error())
		viewErrorAndExit(T("errorMainWindow: ")+""+err.Error(), "")
	}
	prepareEnv()
	prepareBackgroundImage()

	wi.Window.Mw1.Run()
}

func prepareMainWindow() {
	currentWorkingDirectory, err := os.Executable()
	if err != nil {
		walk.MsgBox(windowMsgBox, "Error", "Unable to get current working directory, please contact your local support.", walk.MsgBoxOK)
	}
	wi.Window = winAgentWindow

	wi.StableCurrentWorkingDirectory = filepath.Dir(currentWorkingDirectory)
	wi.TempPath = os.Getenv("tmp")
	// Access to tmp path
	if wi.TempPath == "" {
		viewErrorAndExit(T("invalidTempPath"), "")
	}
	walk.Resources.SetRootDirPath(wi.TempPath)
}

func prepareEnv() {
	wi.Debug = true
	addNewLinesToDebug("============== PacketFence Provisioning Agent ==============")

	// Internationalization (i18n)
	localeInfo := win.GetThreadUILanguage()
	addNewLinesToDebug("User's locale uint16 is: " + fmt.Sprintf("%v", localeInfo))
	switch localeInfo {
	case SUBLANG_FRENCH, SUBLANG_FRENCH_CANADIAN, SUBLANG_FRENCH_BELGIAN, SUBLANG_FRENCH_LUXEMBOURG, SUBLANG_FRENCH_MONACO, SUBLANG_FRENCH_SWISS:
		languageFileName := "fr.json"
		createLanguageFile(wi.StableCurrentWorkingDirectory, FRENCH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("fr")
		addNewLinesToDebug("Program will be translated in french.")
	default:
		languageFileName := "en.json"
		createLanguageFile(wi.StableCurrentWorkingDirectory, ENGLISH_TRANSLATION, languageFileName)
		i18n.MustLoadTranslationFile(languageFileName)
		T, _ = i18n.Tfunc("en")
		addNewLinesToDebug("Program will be translated in english.")
	}

	wi.PngFileName = "pf_bg.png"
	wi.PngFilePath = wi.TempPath + "\\" + wi.PngFileName
	wi.UserCertPath = ""
	wi.ProfilePath = wi.TempPath + "\\profile.xml"
	wi.TemplateOutPath = wi.TempPath + "\\template-out.xml"
	wi.UserCertPath = wi.TempPath + "\\" + "certificate.p12"

	wi.Debug = false
}

func fetchPortalDomainName() {
	// Download mobileconfig file
	err := writeURLToLocalFile(wi.ProfilePath, PROFILE_URL)
	if err != nil {
		viewErrorAndExit(T("cannotRetrieveProfileFile"), err.Error())
	} else {
		// Read xml profile, convert to string
		data, err := ioutil.ReadFile(wi.ProfilePath)
		if err != nil {
			viewErrorAndExit(T("cannotReadProfileData"), err.Error())
		} else {
			// Decode converted xml profile
			dataToString := string(data)
			buffer := bytes.NewReader([]byte(dataToString))
			decoder := plist.NewDecoder(buffer)
			err = decoder.Decode(&wi.XmlPlistProfile)
			if err != nil {
				viewErrorAndExit(T("cannotDecodeProfileFile"), err.Error())
			} else {
				fetchXML()
			}
		}
	}
}

func fetchXML() {
	// Get data from the mobileconfig file
	shouldConfigureWifi := false
	shouldConfigureWired := false
	sum := 0

	// Get PayloadContent length
	lengthPayloadContent := len(wi.XmlPlistProfile["PayloadContent"].([]interface{}))

	for i := 0; i < lengthPayloadContent; i++ {
		payloadContent := wi.XmlPlistProfile["PayloadContent"].([]interface{})[i].(map[string]interface{})
		payloadType := payloadContent["PayloadType"].(string)

		switch payloadType {
		// Wireless configuration
		case "com.apple.wifi.managed":
			shouldConfigureWifi = true
			// get dict index
			wi.WifiIndex = i
			// Get the EAP type to avoid importing the RADIUS cert as a CA
			eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
			if ok {
				wi.EapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
				addNewLinesToDebug("Extract Wireless configuration profile: " + fmt.Sprint(wi.EapType))
			} else {
				viewErrorAndExit("Failed Extract Wireless configuration profile", fmt.Sprint(wi.EapType))
			}
		// Wired configuration
		case "com.apple.firstactiveethernet.managed":
			shouldConfigureWired = true
			wi.WiredIndex = i
			eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
			if ok {
				wi.EapType = eapClientConfiguration["AcceptEAPTypes"].([]interface{})[0].(uint64)
				addNewLinesToDebug("Extract Wired configuration profile: " + fmt.Sprint(wi.EapType))
			} else {
				viewErrorAndExit("Failed Extract Wired configuration profile", fmt.Sprint(wi.EapType))
			}
		// User certificate configuration
		case "com.apple.security.pkcs12":
			wi.UserCert = payloadContent["PayloadContent"].(string)
			wi.Err = createCertTempFile(wi.UserCert, wi.UserCertPath)
			if wi.Err != nil {
				viewErrorAndExit(T("cannotGenerateCertificateFile"), wi.Err.Error())
			} else {
				wi.Err = addCertToMachine(wi.UserCertDecode, CERTUTIL_PROGRAM_PATH)
				if wi.Err != nil {
					viewErrorAndExit(T("cannotDecodeProfileFile"), wi.Err.Error())
				}
			}
		// Certificate of Authority configuration
		case "com.apple.security.root":
			if wi.EapType == EAPTYPE_TLS {
				wi.CaName = payloadContent["PayloadCertificateFileName"].(string)
				wi.CaCert = payloadContent["PayloadContent"].(string)
				wi.CaFilePath = wi.TempPath + "\\" + wi.CaName + ".cer"
				wi.Err = createCertTempFile(wi.CaCert, wi.CaFilePath)
				if wi.Err != nil {
					viewErrorAndExit(T("cannotGenerateCAFile"), wi.Err.Error())
				}
				wi.Err = addCAToMachine(wi.CaFileBinary, CERTUTIL_PROGRAM_PATH)
				if wi.Err != nil {
					viewErrorAndExit(T("cannotDecodeProfileFile"), wi.Err.Error())
				}
			}
		default:
			viewErrorAndExit(T("Unexpected PayloadType."), fmt.Sprint(map[string]interface{}{"PayloadType": payloadType}))
		}
		sum += i
	}
	if shouldConfigureWifi {
		configureWifi()
	}
	if shouldConfigureWired {
		configureWired()
	}
}

// Configure wifi
func configureWifi() {
	var WLAN_ERROR_MESSAGE = T("wlanErrorMessage")
	var templateToFile string
	var elementsToReplaceInTemplate Template
	var wifiKey string
	// Get SSID information
	payloadContent := wi.XmlPlistProfile["PayloadContent"].([]interface{})[wi.WifiIndex].(map[string]interface{})
	ssidString := payloadContent["SSID_STR"].(string)
	ssidStringToHex := hex.EncodeToString([]byte(ssidString))
	ssidBroadcast := payloadContent["HIDDEN_NETWORK"].(bool)
	securityType := payloadContent["EncryptionType"].(string)
	if securityType == "None" {
		securityType = "open"
	}

	// Security of the SSID
	eapClientConfiguration, ok := payloadContent["EAPClientConfiguration"].(map[string]interface{})
	if ok {
		userAuth, ok := eapClientConfiguration["UserName"].(string)
		if ok {
			if userAuth == "" {
				userAuth = "certificate"
			}
		} else {
			userAuth = "certificate"
		}
		if wi.EapType == EAPTYPE_PEAP {
			// Search specific fields in wintemplate and replace them
			elementsToReplaceInTemplate = Template{
				ProfileName:     ssidString,
				SsidStringToHex: ssidStringToHex,
				IsSSIDBroadcast: ssidBroadcast,
				SecAuth:         "WPA2",
				Encryption:      "AES",
			}
			// executes the template
			templateToFile = executeTemplate(WIFI_PEAP_TEMPLATE_NAME, WIFI_PEAP_TEMPLATE, elementsToReplaceInTemplate)
		} else if wi.EapType == EAPTYPE_TLS {
			caFingerprint, err := getCAFingerprint(wi.CaFileBinary)
			if err != nil {
				viewErrorAndExit(T("Unable to get CA fingerprint."), err.Error())
			}
			elementsToReplaceInTemplate = Template{
				ProfileName:     ssidString,
				SsidStringToHex: ssidStringToHex,
				IsSSIDBroadcast: ssidBroadcast,
				SecAuth:         "WPA2",
				Encryption:      "AES",
				CaToTrust:       caFingerprint,
			}
			templateToFile = executeTemplate(WIFI_TLS_TEMPLATE_NAME, WIFI_TLS_TEMPLATE, elementsToReplaceInTemplate)
		} else {
			// error handling
			viewErrorAndExit(T("unexpectedEAPType"), fmt.Sprint(wi.EapType))
		}
		addNewLinesToDebug("EAPType is " + fmt.Sprint(wi.EapType))
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
		templateToFile = executeTemplate(WIFI_OPEN_TEMPLATE_NAME, WIFI_OPEN_TEMPLATE, elementsToReplaceInTemplate)
	}
	// creates profile file with the executed template
	createProfileFile(templateToFile)
	// prepare command line
	wi.WlanCmd = exec.Command("netsh", "wlan", "add", "profile", "filename="+wi.TemplateOutPath, "user=all")
	wlanSuccessMessage := T("The wireless profile was successfully added to the machine. \nPlease select your newly added profile " + ssidString + " in the WiFi networks.")
	// adds the new profile to Windows with netsh command
	addProfileToMachine(wi.WlanCmd, WLAN_ERROR_MESSAGE, wlanSuccessMessage)
}

// Configuration for wired
func configureWired() {
	var WIRED_ERROR_MESSAGE = T("wiredErrorMessage")
	var WIRED_SUCCESS_MESSAGE = T("wiredSuccessMessage")

	dot3svc := exec.Command("net", "start", "dot3svc")
	dot3svc.Start()
	if err := dot3svc.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitStatus := status.ExitStatus()
				if exitStatus != 2 {
					viewErrorAndExit(T("dot3svcFail"), err.Error())
				} else {
					addNewLinesToDebug("The Wired Autoconfig service has been started")
				}
			}
		}
	}
	// creates profile file with the executed template
	if wi.EapType == EAPTYPE_PEAP {
		createProfileFile(WIRED_PEAP_TEMPLATE)
	} else if wi.EapType == EAPTYPE_TLS {
		createProfileFile(WIRED_TLS_TEMPLATE)
	} else {
		// error handling
		wi.Err = errors.New("Not good EAP type: " + fmt.Sprint(wi.EapType))
		viewErrorAndExit(T("unexpectedEAPType"), wi.Err.Error())
	}
	// prepare command line
	wi.WiredCmd = exec.Command("netsh", "lan", "add", "profile", "filename="+wi.ProfilePath)
	// adds the new profile to Windows with netsh command
	addProfileToMachine(wi.WiredCmd, WIRED_ERROR_MESSAGE, WIRED_SUCCESS_MESSAGE)
}

// Create, parse and execute templates
func executeTemplate(nameTemplate, constTemplate string, templateToApply Template) string {
	newTemplate := template.New(nameTemplate)
	var templateBuffer bytes.Buffer
	// parses template
	newTemplate, err := newTemplate.Parse(constTemplate)
	if err != nil {
		viewErrorAndExit(T("cannotParseTemplate"), err.Error())
	} else {
		// executes the template into the open file
		err = newTemplate.Execute(&templateBuffer, templateToApply)
		if err != nil {
			viewErrorAndExit(T("cannotExecuteTemplate"), err.Error())
		} else {
			addNewLinesToDebug(T("executetemplateSuccess"))
		}
	}
	return templateBuffer.String()
}

// Create and write profile file into templateToFile folder
func createProfileFile(templateToFile string) {
	// create and open file
	templateFile, _ := createFile(wi.TemplateOutPath)
	// write the template into the new file
	_, err := io.Copy(templateFile, strings.NewReader(templateToFile))
	if err != nil {
		viewErrorAndExit(T("cannotWriteIntoProfileFile"), err.Error())
	} else {
		addNewLinesToDebug(T("profileCreationSuccess"))
	}
}

// Add wired and wireless profiles to Windows
func addProfileToMachine(cmd *exec.Cmd, ErrorMessage, SuccessMessage string) {
	output, err := cmd.CombinedOutput()
	if err != nil {
		cmdLine := fmt.Sprintf("==> Executing: %s\r\n", strings.Join(cmd.Args, " "))
		errorMess := ErrorMessage + "\r\n"
		errorOut := "Error: " + err.Error() + "\r\n"
		outputOut := "Output: " + fmt.Sprint(output) + "\r\n"
		viewErrorAndExit("Failed adding profile", cmdLine+errorMess+errorOut+outputOut)
	} else {
		addNewLinesToDebug("Success adding profile" + SuccessMessage)
		cleanAndExit(0)
	}
}
