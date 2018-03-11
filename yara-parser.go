package main

import (
	"log"
	"os"
	"yara-parser/grammar"
)

func main() {
	input, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	result := grammar.Parse(input, os.Stdout)
	log.Printf("Result: %d\n", result)

	log.Printf("RuleSet: %v\n", grammar.ParsedRuleset)
}
