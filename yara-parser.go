package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Northern-Lights/yara-parser/grammar"
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

	j, err := json.MarshalIndent(&ruleset, "", "   ")
	if err != nil {
		log.Fatalf("JSON error: %s\n", err)
	}
	fmt.Printf("JSON:\n%s\n", string(j))
}
