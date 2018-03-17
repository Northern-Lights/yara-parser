package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
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

	return o
}

// Defer this to report any errors in deferred functions
func handleErr(f func() error) {
	err := f()
	if err != nil {
		perror(`Error: %s`, err)
		os.Exit(127)
	}
}

func main() {
	opts = getopt()

	yaraFile, err := os.Open(opts.Infile)
	if err != nil {
		perror(`Couldn't open YARA file "%s": %s`, opts.Infile, err)
		os.Exit(2)
	}
	defer handleErr(yaraFile.Close)

	ruleset, err := grammar.Parse(yaraFile, os.Stdout)
	if err != nil {
		perror(`Couldn't parse YARA ruleset: %s`, err)
		os.Exit(3)
	}
	ruleset.File = opts.Infile

	jdata, err := json.MarshalIndent(&ruleset, "", "   ")
	if err != nil {
		perror(`Couldn't marshal ruleset to JSON: %s`, err)
		os.Exit(4)
	}

	// Set output to stdout if not specified; otherwise file
	var out io.Writer
	if opts.Outfile == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(opts.Outfile)
		if err != nil {
			perror(`Couldn't create output file "%s"`, opts.Outfile)
			os.Exit(5)
		}
		defer handleErr(f.Close)
		out = f
	}

	_, err = out.Write(jdata)
	if err != nil {
		perror(`Couldn't write JSON data to "%s"`, opts.Outfile)
		os.Exit(6)
	}
}
