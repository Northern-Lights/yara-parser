package main

import (
	"flag"
	"os"
)

type options struct {
	Infile  string
	Outfile string
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
