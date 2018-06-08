package main

import (
  "os"
  "log"
  "syscall"

  "os/exec"

  "github.com/lxn/walk"
  . "github.com/lxn/walk/declarative"
)

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
		var	badCertificatePassword = true
		for badCertificatePassword {
			badCertificatePassword = false

			var mw *walk.MainWindow
			var passwordTE *walk.LineEdit

			MainWindow{
				AssignTo: &mw,
				Title:    T("enterCertificatePassword"),
				MinSize:  Size{350, 100},
				Layout:   VBox{},
				Children: []Widget{
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
										log.Print("Exit Status: ", exitStatus)
										switch exitStatus {
										case int(ERROR_INVALID_PASSWORD):
											walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("wrongPassword"), walk.MsgBoxOK)
											badCertificatePassword = true
											mw.Close()
										case int(ERROR_INVALID_DATA):
											walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("invalidCertificate"), walk.MsgBoxOK)
											os.Remove(userCertDecode)
											os.Remove("profile.xml")
											log.Fatal("Invalid certificate: ", exitStatus)
										case int(ERROR_FILE_NOT_FOUND):
											walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotFindCertificateFile"), walk.MsgBoxOK)
											os.Remove(userCertDecode)
											os.Remove("profile.xml")
											log.Fatal("Certificate not found: ", exitStatus)
										default:
											walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotInstallCertificate"), walk.MsgBoxOK)
											os.Remove(userCertDecode)
											os.Remove("profile.xml")
											log.Fatal("Cannot install certificate: ", exitStatus)
										}
									}
								}
							} else {
								walk.MsgBox(windowMsgBox, T("successWindowTitle"), T("certificateInstallationSuccess"), walk.MsgBoxOK)
								log.Println("Certificate successfully installed")
								os.Remove(userCertDecode)
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
func addCAToMachine(eapType uint64, caFileBinary string, CERTUTIL_PROGRAM_PATH string) error {
	var err error
	var ERROR_CANCELED int64
	ERROR_CANCELED = 2147943623
	sum := 0
	addCA := exec.Command(CERTUTIL_PROGRAM_PATH, "-addstore", "-user", "Root", caFileBinary)
	// use Start() and Wait() to specify exit status 1 error
	addCA.Start()
	// error handling
	if err := addCA.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			for i := 0; i < 2; i++ {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					if status.ExitStatus() == int(ERROR_CANCELED) {
						// reprompt user to add certificate to windows
						walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("caErrorCanceled"), walk.MsgBoxOK)
						os.Remove(caFileBinary)
						os.Remove("profile.xml")
						log.Fatal("Failed installing certificate: ", err)
						sum += i
					} else {
						walk.MsgBox(windowMsgBox, T("errorWindowTitle"), T("cannotInstallCA"), walk.MsgBoxOK)
						os.Remove(caFileBinary)
						os.Remove("profile.xml")
						log.Fatal("Failed installing certificate: ", err)
					}
				}
			}
		}
	} else {
		log.Println("CA successfully installed")
		walk.MsgBox(windowMsgBox, T("successWindowTitle"), T("caInstallationSuccess"), walk.MsgBoxOK)
	}
	return err
}
