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

func getopt() options {
	var o options

	flag.StringVar(&o.Outfile, "o", "", "JSON output file")

	flag.Parse()

	if n := flag.NArg(); n != 1 {
		fmt.Printf("Expected 1 input file; found %d\n", n)
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
		fmt.Printf(`Error: %s`, err)
	}
}

func main() {
	opts = getopt()

	yaraFile, err := os.Open(opts.Infile)
	if err != nil {
		fmt.Printf(`Couldn't open YARA file "%s": %s\n`, opts.Infile, err)
		os.Exit(1)
	}
	defer handleErr(yaraFile.Close)

	ruleset, err := grammar.Parse(yaraFile, os.Stdout)
	if err != nil {
		fmt.Printf(`Couldn't parse YARA ruleset: %s\n`, err)
		os.Exit(1)
	}
	ruleset.File = opts.Infile

	jdata, err := json.MarshalIndent(&ruleset, "", "   ")
	if err != nil {
		fmt.Printf(`Couldn't marshal ruleset to JSON: %s\n`, err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(opts.Outfile, jdata, os.FileMode(0644))
	if err != nil {
		fmt.Printf(`Couldn't write JSON data to "%s"\n`, opts.Outfile)
	}
}
