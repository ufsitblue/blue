package main

import (
	"fmt"
	"log"
	"os"
	"time"
	//"bufio"
	. "github.com/logrusorgru/aurora"
)

var (
	logger *log.Logger
	tabs   string
)

func InitLogger() {
	logger = log.New(os.Stdout, "", 0)
}

func Tabber(tabnum int) {
	tabs = ""
	for i := 0; i < tabnum; i++ {
		tabs += "\t"
	}
}

func Time() string {
	return time.Now().Format("03:04:05PM")
}

func Stdout(i instance, a ...interface{}) {
	var f *os.File
	logger.Printf("%s%s%s%s%s", Green(""), Brown(""), Red(""), BrightCyan(""), BrightCyan(""))
	logger.Printf("%s%s:%s%s\n%s", tabs, BrightCyan("[STDOUT"), Summary(i), BrightCyan("]"), White(fmt.Sprintln(a...)))
	if !(len(*outfile) == 0){
		f, _ = os.Create("output/"+i.Outfile)
	}
	fmt.Fprintf(f, "%s", fmt.Sprintln(a...))
}

func Stderr(i instance, a ...interface{}) {
	logger.Printf("%s%s:%s%s\n%s", tabs, BrightRed("[STDERR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
}

func Crit(i instance, a ...interface{}) {
	logger.Printf("%s%s:%s%s %s", tabs, Red("[CRIT"), Summary(i), Red("]"), fmt.Sprintln(a...))
}

func Err(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightRed("[ERROR]"), fmt.Sprintln(a...))
}

func ErrExtra(i instance, a ...interface{}) {
	logger.Printf("%s%s:%s%s %s", tabs, BrightRed("[ERROR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
}

func Fatal(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightRed("[FATAL]"), fmt.Sprintln(a...))
	os.Exit(1)
}

func Warning(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, Yellow("[WARN]"), fmt.Sprintln(a...))
}

func Info(a ...interface{}) {
	if !*quiet {
		logger.Printf("%s%s %s", tabs, BrightCyan("[INFO]"), fmt.Sprintln(a...))
	}
}

func InfoExtra(i instance, a ...interface{}) {
	if !*quiet {
		logger.Printf("%s%s:%s%s %s", tabs, BrightCyan("[INFO"), Summary(i), BrightCyan("]"), fmt.Sprintln(a...))
	}
}

func Debug(a ...interface{}) {
	if *debug {
		logger.Printf("%s%s %s", tabs, Cyan("[DEBUG]"), fmt.Sprintln(a...))
	}
}

func DebugExtra(i instance, a ...interface{}) {
	if *debug {
		logger.Printf("%s%s:%s%s %s", tabs, Cyan("[DEBUG"), Summary(i), Cyan("]"), fmt.Sprintln(a...))
	}
}

func Summary(i instance) string {
	if i.Script == "" {
		return fmt.Sprintf("%d:%s:%s", Blue(i.ID), BrightRed(i.Username), BrightGreen(i.IP))
	}
	return fmt.Sprintf("%d@%s:%s:%s:%s/%s", Blue(i.ID), Time(), BrightRed(i.Username), BrightGreen(i.IP), BrightGreen(i.Hostname), BrightBlue(i.Script))
}
