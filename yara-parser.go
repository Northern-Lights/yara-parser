package main

import (
	"fmt"
	"log"
	"os"
	"yara-parser/grammar"
)

func main() {
	input, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	ruleset, err := grammar.Parse(input, os.Stdout)
	if err != nil {
		log.Fatalf(`Parsing failed: "%s"`, err)
	}

	fmt.Printf("Ruleset:\n%v\n", ruleset)
}
