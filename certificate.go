package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"crypto/sha1"
	"encoding/hex"
	"os/exec"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

// Get CA fingerprint
func getCAFingerprint(caFileBinary string) (string, error) {
	var err error
	var caFingerprint string
	// open certificate of authority binary file
	caFile, err := os.Open(caFileBinary)
	if err != nil {
		viewErrorAndExit(T("cannotOpenCAFile"), err.Error())
		defer caFile.Close()
		return "", err
	} else {
		// close file
		defer caFile.Close()

		// create new hash
		hashSha1 := sha1.New()
		// copy hash to the file
		if _, err := io.Copy(hashSha1, caFile); err != nil {
			viewErrorAndExit(T("cannotCopyCAFile"), err.Error())
			return "", err
		} else {
			// returns sha1 checksum of the data
			caFingerprintBytes := hashSha1.Sum(nil)
			// convert sha1 to hex (base16) to string
			caFingerprint = strings.ToLower(hex.EncodeToString(caFingerprintBytes))
			// add spaces every two characters
			for i := 2; i < len(caFingerprint); i += 3 {
				caFingerprint = caFingerprint[:i] + " " + caFingerprint[i:]
			}
			return caFingerprint, nil
		}
	}
}

// Add cert to windows
func addCertToMachine(userCertDecode string, CERTUTIL_PROGRAM_PATH string) error {
	// must use var instead of const to specify int64 type (otherwise not working on 32bit Windows machines)
	var err error
	var ERROR_INVALID_PASSWORD int64
	var ERROR_INVALID_DATA int64
	var ERROR_FILE_NOT_FOUND int64
	ERROR_INVALID_PASSWORD = 2147942486
	ERROR_INVALID_DATA = 2147942413
	ERROR_FILE_NOT_FOUND = 2147942402

	if userCertDecode != "" {
		var badCertificatePassword = true
		for badCertificatePassword {
			badCertificatePassword = false

			var mw *walk.MainWindow
			var passwordTE *walk.LineEdit

			MainWindow{
				AssignTo: &mw,
				Title:    PROGRAM_NAME,
				MinSize:  Size{Width: 350, Height: 100},
				Layout:   VBox{},
				Children: []Widget{
					Label{Text: T("enterCertificatePassword")},
					LineEdit{AssignTo: &passwordTE, PasswordMode: true},
					PushButton{
						Text: "OK",
						OnClicked: func() {
							// prompt user for certificate password
							certPassword := passwordTE.Text()
							addCertificate := exec.Command(CERTUTIL_PROGRAM_PATH, "-f", "-user", "-p", certPassword, "-importpfx", userCertDecode)
							addCertificateIn, _ := addCertificate.StdinPipe()
							addCertificate.Start()
							addCertificateIn.Write([]byte(CERTUTIL_PROGRAM_PATH + "-f -user -p " + certPassword + " -importpfx " + userCertDecode))
							addCertificateIn.Close()
							// error handling
							if err = addCertificate.Wait(); err != nil {
								if exitErr, ok := err.(*exec.ExitError); ok {
									if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
										exitStatus := status.ExitStatus()
										addNewLinesToDebug("Exit Status: " + fmt.Sprint(exitStatus))
										switch exitStatus {
										case int(ERROR_INVALID_PASSWORD):
											viewErrorAndExit(T("wrongPassword"), "")
											badCertificatePassword = true
											mw.Close()
										case int(ERROR_INVALID_DATA):
											viewErrorAndExit(T("invalidCertificate"), "")
										case int(ERROR_FILE_NOT_FOUND):
											viewErrorAndExit(T("cannotFindCertificateFile"), " => "+fmt.Sprint(exitStatus))
										default:
											viewErrorAndExit(T("cannotInstallCertificate"), " => "+fmt.Sprint(exitStatus))
										}
									}
								}
							} else {
								addNewLinesToDebug(T("certificateInstallationSuccess"))
							}
							mw.Close()
						},
					},
				},
			}.Run()
		}
	}
	return err
}

// Add CA to the machine
func addCAToMachine(caFileBinary string, CERTUTIL_PROGRAM_PATH string) error {
	var err error
	ERROR_CANCELED := 2147943623
	runCommand := true
	for runCommand {
		runCommand = false
		addCA := exec.Command(CERTUTIL_PROGRAM_PATH, "-addstore", "-user", "Root", caFileBinary)
		// use Start() and Wait() instead of Run() to specify exit status 1 error
		addCA.Start()
		// error handling
		if err := addCA.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					if status.ExitStatus() == int(ERROR_CANCELED) {
						// reprompt user to add certificate to windows
						retryOrCancel := walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("caErrorCanceled"), walk.MsgBoxRetryCancel)
						if retryOrCancel == 4 {
							addNewLinesToDebug("Failed installing certificate: " + err.Error())
							runCommand = true
						} else {
							addNewLinesToDebug("Failed installing certificate: " + err.Error())
						}
					} else {
						viewErrorAndExit(T("cannotInstallCA"), err.Error())
					}
				}
			}
		} else {
			addNewLinesToDebug(T("caInstallationSuccess") + err.Error())
		}
	}
	return err
}
