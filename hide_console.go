package main

import (
  "github.com/gonutz/ide/w32"
)

func hideConsole() {
    console := w32.GetConsoleWindow()
    if console == 0 {
        return // no console attached
    }
    // If this application is the process that created the console window, then
    // this program was not compiled with the -H=windowsgui flag and on start-up
    // it created a console along with the main application window. In this case
    // hide the console window.
    // See
    // http://stackoverflow.com/questions/9009333/how-to-check-if-the-program-is-run-from-a-console
    _, consoleProcID := w32.GetWindowThreadProcessId(console)
    if w32.GetCurrentProcessId() == consoleProcID {
        w32.ShowWindowAsync(console, w32.SW_HIDE)
    }
}
