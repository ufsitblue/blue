package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// Running states
	RUN_WAIT = iota
	RUN_ACTIVE
	RUN_ERROR
	RUN_END
)

const (
	RANDSTRLEN = 12
)

const (
	// Parsing states
	NONE = iota
	IF
	IF_FALSE
	ELSE
	ROULETTE_WAITING
	ROULETTE_TRUE
	ROULETTE_RAN
	OUTPUT_ACTIVE
)

var (
	rouletteRoll    int
	rouletteCounter int
)

type scriptState struct {
	Output      bool
	Conditional uint
	Roulette    uint
}

var ExitString string

func isPortOpen(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func ssherWrapper(i instance) {
	var wg sync.WaitGroup
	var err error
	var sess *ssh.Session

	// Distribute files over X threads
	first := true
	scriptChan := make(chan string)
	exitChan := make(chan bool)
	sess, err = connect(i)
	for t := 0; t < *threads && t < len(scripts); t++ {
		if first {
			first = false
		} else {
			sess, err = connect(i)
			if err != nil {
				Err("Login failed for known good creds! Have we been bamboozled? Error:", err)
				continue
			}
		}
		wg.Add(1)
		go ssher(i, sess, scriptChan, exitChan, &wg)
		i.ID++
	}

	// Will send doneChan to kill watchdog.
	doneChan := make(chan bool)
	go watchdog(i, scriptChan, exitChan, doneChan, &wg)

	for _, s := range scripts {
		scriptChan <- s
	}

	close(scriptChan)
	doneChan <- true

	wg.Wait()
}

// Normal runner, taking in a user/password list
func runner(ip string, outfile string, w *sync.WaitGroup) {
	defer w.Done()
	var err error
	found := false
	deadHost := false
	ExitString = randomString(RANDSTRLEN)
	i := instance{
		IP:      ip,
		Outfile: outfile,
	}

	for _, u := range usernameList {
		if found || deadHost {
			break
		}
		for _, p := range passwordList {
			i.Username = u
			i.Password = p
			if *debug && *passwords != "" {
				InfoExtra(i, "Trying password '"+i.Password+"'")
			}
			_, err = connect(i)
			if err != nil && strings.Contains(err.Error(), "Could not connect") {
				Debug(fmt.Sprintf("Port %d is closed on %s", *port, i.IP))
				deadHost = true
				break
			}
			if err == nil {
				InfoExtra(i, "Valid credentials for", i.Username)
				found = true
				i.Username = u
				i.Password = p
				break
			}
		}
	}

	if !found {
		if err != nil && strings.Contains(err.Error(), "Could not connect") {
			return
		}
		ErrExtra(i, "Login attempts failed!")
		return
	}

	ssherWrapper(i)
}

// Nothing like more janky by redefining the runner for individual cred sets
func GeraldRunner(ip string, outfile string, w *sync.WaitGroup, username string, password string) {
	defer w.Done()
	found := false
	ExitString = randomString(RANDSTRLEN)
	i := instance{
		IP:       ip,
		Outfile:  outfile,
		Username: username,
		Password: password,
	}
	_, err := connect(i)
	if err != nil && strings.Contains(err.Error(), "Could not connect") {
		Debug(fmt.Sprintf("Port %d is closed on %s", *port, i.IP))
	}
	if err == nil {
		InfoExtra(i, "Valid credentials for", i.Username)
		found = true
	}
	if !found {
		if err != nil && strings.Contains(err.Error(), "Could not connect") {
			return
		}
		ErrExtra(i, "Login attempts failed!")
		return
	}

	ssherWrapper(i)
}

// watchdog will see if connections die, and then spawns new ones.
func watchdog(i instance, scriptChan chan string, exitChan, doneChan chan bool, wg *sync.WaitGroup) {
	for {
		select {
		case <-doneChan:
			DebugExtra(i, "Last script has been claimed, so watchdog is exiting.")
			return
		case <-exitChan:
			DebugExtra(i, "Watchdog saw that a session died! Starting up another...")
			sess, err := connect(i)
			if err != nil {
				Err("Login failed for known good creds! Have we been bamboozled? Error:", err)
				continue
			}
			wg.Add(1)
			go ssher(i, sess, scriptChan, exitChan, wg)
			i.ID++
		}
	}
}

func keyboardInteractive(password string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		// Just send the password back for all questions
		// (from terraform)
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = string(password)
		}
		return answers, nil
	}
}

func connect(i instance) (*ssh.Session, error) {

	// SSH client config
	config := &ssh.ClientConfig{
		User: i.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(i.Password),
			ssh.KeyboardInteractive(keyboardInteractive(i.Password)),
		},
		Timeout: timeout,
		// We don't care about host key verification
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Ensure host has ssh open
	if !isPortOpen(i.IP, *port) {
		err := errors.New(fmt.Sprintf("Could not connect to %s:%d", i.IP, *port))
		return &ssh.Session{}, err
	}

	// Connect to host
	client, err := ssh.Dial("tcp", i.IP+":"+strconv.Itoa(*port), config)
	if err != nil {
		InfoExtra(i, "Login failed :(. Error:", err)
		return &ssh.Session{}, err
	} else {
		// Create sesssion
		sess, err := client.NewSession()

		if err != nil {
			Info("Session creation failed :(")
		} else {
			return sess, nil
		}
	}

	return nil, nil
}

func ssher(i instance, sess *ssh.Session, scriptChan chan string, exitChan chan bool, wg *sync.WaitGroup) {

	ManualExit := false
	ScriptChanDone := false
	//noodle
	defer func() {
		if !ManualExit {
			exitChan <- true
		} else {
			if !ScriptChanDone {
				_, _ = <-scriptChan
			}
		}
	}()
	defer sess.Close()
	defer wg.Done()

	// I/O for shell
	stdin, err := sess.StdinPipe()
	if err != nil {
		Err(err)
		return
	}

	var stdoutBytes bytes.Buffer
	var stderrBytes bytes.Buffer
	sess.Stdout = &stdoutBytes
	sess.Stderr = &stderrBytes
	var stdoutOffset int
	var stderrOffset int

	// Start remote shell
	err = sess.Shell()
	if err != nil {
		Err(err)
		return
	}

	index := 1
	escalated := false

	InfoExtra(i, "Interactive shell on", i.IP)

	// Initial wait to let the normal stdout flow from MOTD
	time.Sleep(1 * time.Second)

	// Safe to asssume all systems have whoami. If whoami returns nothing, stdin is prob borked for this shell (fish)
	origStdOut := stdoutBytes
	fmt.Fprintf(stdin, "whoami\n")
	time.Sleep(250 * time.Millisecond)
	difference := strings.Replace(stdoutBytes.String(), origStdOut.String(), "", -1)
	difference = strings.Replace(difference, "\n", "", -1)
	if len(difference) == 0 {
		ManualExit = true
		Crit(i, "Coordinate stdin is borked on this host!")
		BrokenHosts = append(BrokenHosts, i.IP)
		return
	}

	if !*noValidate {
		if !validateShell(i, stdin, &stdoutBytes, stdoutOffset) {
			Crit(i, "Shell did not respond (to echo) before timeout!")
			return
		} else {
			DebugExtra(i, "Shell appears to be valid (echoes back successfully).")
		}
	}

	stdoutOffset = stdoutBytes.Len()
	stderrOffset = stderrBytes.Len()

	if i.Username != "root" {

		// If su is enabled, try to su to root.
		if *su != "" {
			fmt.Fprintf(stdin, "su\n")
			time.Sleep(2 * time.Second)
			stderrOffset = stderrBytes.Len()
			DebugExtra(i, "Trying password", *su, "with su")
			fmt.Fprintf(stdin, "%s\n", *su)
			time.Sleep(4 * time.Second)
			if stderrBytes.Len()-stderrOffset > 0 {
				Stderr(i, strings.TrimSpace(stderrBytes.String()))
				Crit(i, "Failed to escalate from", i.Username, "to root (via su) on", i.IP)
				//return
			} else {
				InfoExtra(i, "Successfully escalated to root (via su).")
				escalated = true
			}
		}

		// If sudo is enabled, and we're not already root, attempt to escalate.
		if *sudo && !escalated {
			fmt.Fprintf(stdin, "sudo -i\necho\n")
			time.Sleep(2 * time.Second)
			// Password: prompt should be stderr even if no error is printed in time
			if stderrBytes.Len()-stderrOffset == 0 {
				InfoExtra(i, "Password-less sudo permitted, escalated to root.")
			} else { //yoinky sploinky
				stderrOffset = stderrBytes.Len()
				//fmt.Fprintf(stdin, "sudo -S su\n%s\n", i.Password)
				fmt.Fprintf(stdin, "sudo -Si \n%s\n", i.Password)
				//Compare stdout to check if i am root
				origStdOut := stdoutBytes
				fmt.Fprintf(stdin, "whoami\n")
				time.Sleep(2 * time.Second)
				/*
					fmt.Printf("Orig -> %s\n", origStdOut.String())
					fmt.Printf("Orig Length is -> %d\n", origStdOut.Len())
					fmt.Printf("Current -> %s\n", stdoutBytes.String())
					fmt.Printf("Current Length is -> %d\n", stdoutBytes.Len())
				*/
				difference := strings.Replace(stdoutBytes.String(), origStdOut.String(), "", -1)
				difference = strings.Replace(difference, "\n", "", -1)
				/*
					fmt.Printf("Difference -> %s \n", difference)
					fmt.Printf("Difference Length -> %d\n", len(difference))
				*/
				if difference != "root" {
					Crit(i, "Failed to escalate from", i.Username, "to root (via sudo) on", i.IP)
					fmt.Printf("Error was: %s", stderrBytes.String())
					return
				}

				InfoExtra(i, "Successfully elevated to root (via sudo).")
			}
		}
	}

	// Compare stdout to check hostname
	origStdOut = stdoutBytes
	fmt.Fprintf(stdin, "hostname\n")
	time.Sleep(500 * time.Millisecond)

	Debug(fmt.Sprintf("Orig -> %s", origStdOut.String()))
	Debug(fmt.Sprintf("Orig Length is -> %d", origStdOut.Len()))
	Debug(fmt.Sprintf("Current -> %s", stdoutBytes.String()))
	Debug(fmt.Sprintf("Current Length is -> %d", stdoutBytes.Len()))

	difference = strings.Replace(stdoutBytes.String(), origStdOut.String(), "", -1)
	difference = strings.Replace(difference, "\n", "", -1)
	Debug(fmt.Sprintf("Difference -> %s", difference))

	// Read from /etc/hostname is hostname returns no stdout (doesn't exist)
	// This will not work at all if theres no /etc/hostname (e.g: /etc/sysconfig/network)
	// But hopefully we don't run into that edge case? :flushed:
	if len(difference) == 0 {
		Debug(fmt.Sprintf("Hostname returned nothing, reading from /etc/hostname"))
		origStdOut = stdoutBytes
		fmt.Fprintf(stdin, "cat /etc/hostname\n")
		time.Sleep(1 * time.Second)
		difference = strings.Replace(stdoutBytes.String(), origStdOut.String(), "", -1)
		difference = strings.Replace(difference, "\n", "", -1)
		Debug(fmt.Sprintf("Difference -> %s", difference))

		// Worst case, we don't know
		if len(difference) == 0 {
			difference = i.IP
		}
	}
	i.Hostname = difference
	i.Outfile = difference + "." + i.Outfile
	Debug(fmt.Sprintf("Printing output to -> %s", i.Outfile))

	_, err = fmt.Fprintf(stdin, "/bin/sh\n")
	time.Sleep(1 * time.Second)

	if err != nil {
		Crit(i, "Error spawning /bin/sh", err)
		return
	}

	for {
		script, ok := <-scriptChan
		if !ok {
			return
		}
		ScriptChanDone = true
		i.Script = script

		// read file for module
		file, err := os.Open(script)
		if err != nil {
			Crit(i, errors.New("Error opening "+i.Script+": "+err.Error()))
			return
		}
		defer file.Close()

		var state scriptState

		scanner := bufio.NewScanner(file)
		scriptRan := true
		index = 0

		stdoutOffset = stdoutBytes.Len()
		stderrOffset = stderrBytes.Len()

		if len(environCmds) != 0 {
			for _, cmd := range environCmds {
				_, err = fmt.Fprintf(stdin, "%s\n", cmd)
				if err != nil {
					Crit(i, "Error submitting environmental command to stdin:", err)
					break
				}
			}
		}

		for scanner.Scan() {
			index++

			line, err := interpret(scanner.Text(), index, i, &state)
			if err != nil {
				Crit(i, errors.New("Error: "+i.Script+": "+err.Error()))
				break
			}

			// If the input line is blank, or interpret returned an empty line,
			// move along
			if line == "" {
				continue
			}

			// Prepend exit 1 with an echo [string] that we can search for later
			// To determine if the script exitted early.
			if line == "exit 1" {
				_, err := fmt.Fprintf(stdin, "echo %s\n", ExitString)
				if err != nil {
					Crit(i, "Error submitting exit tag to stdin:", err)
					break
				}
			}

			// Actually send the command to remote
			Debug(fmt.Sprintf("Sending line: %s", line))
			_, err = fmt.Fprintf(stdin, "%s\n", line)
			if err != nil {
				Crit(i, "Error submitting line to stdin:", err)
				Crit(i, "Line was: ", line)
				break
			}

		}

		var randOffset int

		if *noValidate {
			// When we're not validating that a script finishes, just wait for
			// half of the timeout and hope for the best
			DebugExtra(i, "Waiting timeout/2 for script to finish.")
			time.Sleep(timeout / 2)
		} else {

			scriptRan = validateShell(i, stdin, &stdoutBytes, stdoutOffset)

			if !scriptRan {
				Crit(i, "Script didn't finish before timeout! Killing this session...")
			} else {
				InfoExtra(i, "Finished running script!")
				// Add one for the newline
				randOffset = RANDSTRLEN + 1
			}
		}

		if !*errs {
			if stdoutBytes.Len()-stdoutOffset-randOffset > 0 {
				if strings.TrimSpace(stdoutBytes.String()) != "" {
					Stdout(i, strings.TrimSpace(stdoutBytes.String()[stdoutOffset:stdoutBytes.Len()-randOffset]))

					// Incoming giga jank for config creation
					if *CreateConfig {
						TotalOut := strings.TrimSpace(stdoutBytes.String()[stdoutOffset : stdoutBytes.Len()-randOffset])
						for _, line := range strings.Split(TotalOut, "\n") {
							if strings.Split(line, ",")[0] == i.Username {
								Password := strings.Split(line, ",")[1]
								Entry := ConfigEntry{i.IP, i.Username, Password}
								ConfigEntries = append(ConfigEntries, Entry)
							}
						}
					}
				}
			}
		}

		if stderrBytes.Len()-stderrOffset > 0 {
			Stderr(i, strings.TrimSpace(stderrBytes.String()[stderrOffset:]))
		}

		if err := scanner.Err(); err != nil {
			Crit(i, errors.New("scanner error: "+err.Error()))
		}

		if !scriptRan {
			return
		}
	}

	_, err = fmt.Fprintf(stdin, "logout\n")
	if err != nil {
		Crit(i, errors.New("Error submitting logout command: "+err.Error()))
	}

	if escalated {
		_, err = fmt.Fprintf(stdin, "logout\n")
		if err != nil {
			Crit(i, errors.New("Error submitting second logout command: "+err.Error()))
		}
	}

	// Wait for sess to finish with timeout
	errChan := make(chan error)
	go func() {
		errChan <- sess.Wait()
	}()

	select {
	case <-errChan:
	case <-time.After(timeout):
		Err("Shell close wait timed out. Leaving session.")
	}
}

func lineError(s string, lineNum int, line string, err string) error {
	return errors.New(s + ": " + "line " + strconv.Itoa(lineNum) + ": " + err + ": " + line)
}

func interpret(line string, lineNum int, i instance, state *scriptState) (string, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return "", nil
	}

	// string replacements
	if strings.Contains(line, "#CALLBACK_IP") {
		rand.Seed(time.Now().UTC().UnixNano())
		callBack := callbackIPs[rand.Intn(len(callbackIPs))]
		line = strings.Replace(line, "#CALLBACK_IP", callBack, -1)
	}

	if *debug {
		InfoExtra(i, "(line "+strconv.Itoa(lineNum)+")", line)
	}

	/*
		splitLine := strings.Split(line, " ")
			firstChar := line[0]
			switch firstChar {
			case '#':
				if len(splitLine) == 0 {
					return "", nil
				}
				switch splitLine[0] {
				case "#GET":
					// TODO
					return "", nil
				case "#DROP":
					if len(splitLine) != 3 {
						return "", lineError(i.Script, lineNum, line, "malformed drop")
					}

					// TODO: fix insecure file path handling
					//filePath := "../" + m + "/drops/" + splitLine[1]
					filePath := "/etc/passwd"

					fileContent, err := os.ReadFile(filePath)
					if err != nil {
						return "", lineError(i.Script, lineNum, line, "invalid file specified to drop at "+filePath)
					}

					// TODO: if buffer is too large, reset it and offset
					// base64 encode file contents
					encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
					return fmt.Sprintf("echo '%s' | base64 -d > %s", encoded, splitLine[2]), nil
				}
			default:
				return line, nil
			}
	*/
	return line, nil
}

func waitOutput(output *bytes.Buffer, offset int, randStr string) bool {
	for t := 0; t*int(shortTimeout) < int(timeout); t++ {
		if output.Len()-offset >= len(randStr)+1 {
			if strings.Contains(strings.TrimSpace(output.String()[output.Len()-len(randStr)-1:]), randStr) {
				return true
			} else if strings.Contains(strings.TrimSpace(output.String()[output.Len()-len(randStr)-1:]), ExitString) {
				return true
			}
		}
		time.Sleep(shortTimeout)
	}
	return false
}

func validateShell(i instance, stdin io.Writer, output *bytes.Buffer, offset int) bool {
	randStr := randomString(RANDSTRLEN)
	_, err := fmt.Fprintf(stdin, "echo %s\n", randStr)
	if err != nil {
		Crit(i, "Error submitting start validation line to stdin:", err)
		return false
	}
	return waitOutput(output, offset, randStr)
}

func randomString(n int) string {
	var letters = []rune("abcfgikmoqsuvwyABDFHJLMNPRTUWY024579")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
