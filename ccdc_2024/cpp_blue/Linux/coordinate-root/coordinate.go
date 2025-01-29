package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
	"inet.af/netaddr"

	flag "github.com/spf13/pflag"
)

type instance struct {
	ID       int
	IP       string
	Username string
	Password string
	Script   string
	Port     int
	Outfile  string
	Hostname string
}

type Script struct {
	Name          string
	IfState       int
	RouletteState int
	OutputState   int
}

type ConfigEntry struct {
	IP       string
	Username string
	Password string
}

var (
	timeout      time.Duration
	shortTimeout time.Duration
	BrokenHosts  []string
	AnnoyingErrs []string
	TotalRuns    int
)

var (
	CreateConfigScript = `
#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald
CHANGEPASSWORD() {
	BIN=$( which chpasswd || which passwd )
	if echo "$BIN" | grep -qi "chpasswd"; then
		CMD="echo \"$1:$2\" | $BIN"
	elif echo "$BIN" | grep -qi "passwd"; then
		CMD="printf \"$2\\n$2\\n\" | $BIN $1"
	fi
	sh -c "$CMD"
}
echo "username,password"

for user in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -f1 -d':'); do
	pass=$(cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1)
	CHANGEPASSWORD $user $pass > /dev/null 2>&1
	echo "$user,$pass"
done`
)

var (
	port      = flag.IntP("port", "P", 22, "SSH port to use")
	threads   = flag.IntP("limit", "l", 3, "Thread limit per IP")
	timelimit = flag.IntP("timeout", "T", 30, "Time limit per script")
	targets   = flag.StringP("targets", "t", "", "List of target IP addresses (ex., 127.0.0.1-127.0.0.5,192.168.1.0/24)")
	usernames = flag.StringP("usernames", "u", "", "List of usernames")
	passwords = flag.StringP("passwords", "p", "", "List of passwords")
	callbacks = flag.StringP("callbacks", "c", "", "Callback IP address(es)")
	outfile   = flag.StringP("outfile-ext", "o", "", "Output file extension. If not specified, then no output is saved.")
	//key       = flag.StringP("key", "k", "", "Use this SSH key to connect")
	environment  = flag.StringP("env", "E", "", "Set these variables before running scripts")
	quiet        = flag.BoolP("quiet", "q", false, "Print only script output")
	debug        = flag.BoolP("debug", "d", false, "Print debug messages")
	errs         = flag.BoolP("errors", "e", false, "Print errors only (no stdout)")
	noValidate   = flag.BoolP("no-validate", "n", false, "Don't ensure shell is valid, or that scripts have finished running")
	CreateConfig = flag.BoolP("create-config", "C", false, "Create a json config for auth. ONLY COMPATIBLE WITH password.sh. This has no error handling. Have fun.")
	UseConfig    = flag.BoolP("use-config", "U", false, "Use config.json. This has no error handling. Have fun.")
	callbackIPs  = []string{}
	scripts      = []string{}
	usernameList = []string{}
	passwordList = []string{}
	environCmds  = []string{}
	addresses    = []netaddr.IP{}
)

var ConfigEntries = []ConfigEntry{}

func main() {
	InitLogger()
	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	// Set timeouts
	timeout = time.Duration(*timelimit * int(time.Second))
	shortTimeout = time.Duration(*timelimit * 40 * int(time.Millisecond))

	// Fetch scripts
	scripts = flag.Args()

	if (len(scripts) == 0 && !*CreateConfig) || ((*usernames == "" || *targets == "") && !*UseConfig) {
		Err("Missing target(s), script(s), and/or username(s).")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		return
	}

	if *environment != "" {
		environCmds = strings.Split(*environment, ";")
	}

	if *CreateConfig {
		scripts = nil
		scripts = append(scripts, "CREATING_CONFIG")
	}
	if !*UseConfig {
		// Parse IP addresses
		targetTokens := strings.Split(*targets, ",")
		ipSetBuilder := netaddr.IPSetBuilder{}
		for _, t := range targetTokens {
			if i := strings.IndexByte(t, '-'); i != -1 {
				ips, err := netaddr.ParseIPRange(t)
				if err != nil {
					Fatal(err)
				}
				ipSetBuilder.AddRange(ips)
			} else if i := strings.IndexByte(t, '/'); i != -1 {
				ips, err := netaddr.ParseIPPrefix(t)
				if err != nil {
					Fatal(err)
				}
				ipSetBuilder.AddRange(ips.Range())
			} else {
				ip, err := netaddr.ParseIP(t)
				if err != nil {
					Fatal(err)
				}
				ipSetBuilder.Add(ip)
			}
		}

		ipSet, err := ipSetBuilder.IPSet()
		if err != nil {
			Fatal(err)
		}

		stringAddresses := []string{}
		for _, r := range ipSet.Ranges() {
			if r.From().Compare(r.To()) != 0 {
				stringAddresses = append(stringAddresses, r.String())
			} else {
				stringAddresses = append(stringAddresses, r.From().String())
			}
			ip := r.From()
			for ip.Compare(r.To().Next()) != 0 {
				addresses = append(addresses, ip)
				ip = ip.Next()
			}
		}

		if !*quiet {
			fmt.Printf("Specified targets (%d addresses):\n\t%s\n", len(addresses), strings.Join(stringAddresses, "\n\t"))
			fmt.Printf("Specified scripts (%d files):\n\t%s\n", len(scripts), strings.Join(scripts, "\n\t"))
			if len(environCmds) != 0 {
				fmt.Printf("Specified environmental commands (%d items):\n\t%s\n", len(environCmds), strings.Join(environCmds, "\n\t"))
			}
		}

		// If callback IP(s), split them
		if *callbacks != "" {
			callbackIPs = strings.Split(*callbacks, ",")
		}

		// Split usernames
		usernameList = strings.Split(*usernames, ",")
		if *passwords == "" {
			fmt.Print("Password: ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				Fatal(err)
			}
			passwordList = []string{strings.TrimSpace(string(password))}
			fmt.Println()
		} else {
			passwordList = strings.Split(*passwords, ",")
		}
		// Distribute IPs to runner tasks
		var wg sync.WaitGroup
		for _, ip := range addresses {
			wg.Add(1)
			go runner(ip.String(), *outfile, &wg)
		}
		wg.Wait()
	} else {
		// This handles the usage of a config.json
		RawConfig, err := ioutil.ReadFile("config.json")
		var ReadConfigEntries = []ConfigEntry{}
		if err != nil {
			Err(fmt.Sprintf("Error reading config.json: %s", err))
		}
		err = json.Unmarshal(RawConfig, &ReadConfigEntries)
		if err != nil {
			Err(fmt.Sprintf("Error unmarshalling config.json: %s", err))
			return
		}
		if len(ReadConfigEntries) == 0 {
			Err("Config.json has no entries??")
			return
		}
		var wg sync.WaitGroup
		for _, Entry := range ReadConfigEntries {
			wg.Add(1)
			go GeraldRunner(Entry.IP, *outfile, &wg, Entry.Username, Entry.Password)
		}
		wg.Wait()
	}

	if len(BrokenHosts) > 0 {
		Err(fmt.Sprintf("The following hosts had janky ssh and should be configured manually: \n"))
		for _, host := range BrokenHosts {
			fmt.Println(host)
		}
	}

	if *CreateConfig {
		// If a config exists, just add entries
		var ReadConfigEntries = []ConfigEntry{}
		RawConfig, err := os.ReadFile("config.json")
		if !os.IsNotExist(err) {
			err = json.Unmarshal(RawConfig, &ReadConfigEntries)
			if err != nil {
				Err(fmt.Sprintf("Error unmarshalling config.json: %s", err))
			}
		}
		if len(ReadConfigEntries) > 0 {
			for _, entry := range ReadConfigEntries {
				idx := slices.IndexFunc(ConfigEntries, func(c ConfigEntry) bool { return c.IP == entry.IP })
				if idx == -1 {
					ConfigEntries = append(ConfigEntries, entry)
				}
			}
		}

		// Parse ConfigEntries
		Jsonified, err := json.MarshalIndent(ConfigEntries, "", "  ")
		if err != nil {
			Err(fmt.Sprintf("Error marshaling JSON while creating config: %s", err))
			return
		}
		if len(Jsonified) == 2 {
			Err("Config Entries are corrupted. Not writing to config.json")
			return
		}

		os.WriteFile("config.json", Jsonified, 0644)
	}

	if len(AnnoyingErrs) > 0 {
		for _, conerr := range AnnoyingErrs {
			Err(conerr)
		}
	}

	Info(fmt.Sprintf("Total hosts hit: %d\n", TotalRuns))
}
