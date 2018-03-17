package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Northern-Lights/yara-parser/grammar"
)

// global options
var opts options

type options struct {
	Infile  string
	Outfile string
}

func perror(s string, a ...interface{}) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(s, a...))
	sb.WriteRune('\n')
	os.Stderr.WriteString(sb.String())
}

func getopt() options {
	var o options

	flag.StringVar(&o.Outfile, "o", "", "JSON output file")

	flag.Parse()

	if n := flag.NArg(); n != 1 {
		perror("Expected 1 input file; found %d", n)
		os.Exit(1)
	}

	o.Infile = flag.Args()[0]

	if o.Outfile == "" {
		fname := strings.Replace(
			filepath.Base(o.Infile),
			filepath.Ext(o.Infile),
			"",
			1)

		o.Outfile = fmt.Sprintf("%s.json", fname)
	}

	return o
}

// Defer this to report any errors in deferred functions
func handleErr(f func() error) {
	err := f()
	if err != nil {
		perror(`Error: %s`, err)
	}
}

func main() {
	opts = getopt()

	yaraFile, err := os.Open(opts.Infile)
	if err != nil {
		perror(`Couldn't open YARA file "%s": %s`, opts.Infile, err)
		os.Exit(1)
	}
	defer handleErr(yaraFile.Close)

	ruleset, err := grammar.Parse(yaraFile, os.Stdout)
	if err != nil {
		perror(`Couldn't parse YARA ruleset: %s`, err)
		os.Exit(1)
	}
	ruleset.File = opts.Infile

	jdata, err := json.MarshalIndent(&ruleset, "", "   ")
	if err != nil {
		perror(`Couldn't marshal ruleset to JSON: %s`, err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(opts.Outfile, jdata, os.FileMode(0644))
	if err != nil {
		perror(`Couldn't write JSON data to "%s"`, opts.Outfile)
	}
}
