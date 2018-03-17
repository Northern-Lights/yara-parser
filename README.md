# yara-parser

`yara-parser` is a Go library for manipulating YARA rulesets.  Its key feature is that it uses the same grammar and lexer files as the original libyara to ensure that lexing and parsing work exactly like YARA.  The grammar and lexer files have been modified to fill Go data structures for ruleset manipulation instead of compiling rulesets for data matching.

Using `yara-parser`, one will be able to read YARA rulesets to programatically change metadata, rule names, rule modifiers, tags, strings, and more.

The ability to serialize rulesets to JSON for rule manipulation in other languages is provided with the `y2j` tool.

## Installation

### `y2j`: YARA to JSON

Use the following command to install the `y2j` command for converting YARA rulesets to JSON.

`go get -u github.com/Northern-Lights/yara-parser/cmd/y2j`

Of course, this will install `y2j` to `$GOPATH/bin`, so ensure that the latter is in your `$PATH`.

The grammar and lexer files are frozen so that building them with `goyacc` and `flexgo` are not necessary.

### Grammar Library

Use the following command to install the grammar library for deserializing YARA rulesets without installing `y2j`.

`go get -u github.com/Northern-Lights/yara-parser/grammar`

## Development

Currently, there is a `Makefile` which will build the parser, lexer, and main application.  For this to work, the following are needed:

| Command | Source (`go get`) |
| - | - |
| `goyacc` | `golang.org/x/tools/cmd/goyacc` |
| `flexgo` | `github.com/pebbe/flexgo` (Tool must be built manually)|

## Go Usage

Sample usage for working with rulesets in Go looks like the following:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Northern-Lights/yara-parser/grammar"
)

func main() {
	input, err := os.Open(os.Args[1])   // Single argument: path to your file
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	ruleset, err := grammar.Parse(input, os.Stdout)
	if err != nil {
		log.Fatalf(`Parsing failed: "%s"`, err)
	}

    fmt.Printf("Ruleset:\n%v\n", ruleset)
    
    // Manipulate the first rule
    rule := ruleset.Rules[0]
    rule.Identifier = "new_rule_name"
    rule.Modifiers.Global = true
    rule.Modifiers.Private = false
}
```

## Limitations

Currently, there are no guarantees with the library that modified rules will serialize back into a valid YARA ruleset.  For example, you can set `rule.Identifier = "123"`, but this would be invalid YARA.  Additionally, adding or removing strings may cause a condition to become invalid, and conditions are currently treated only as text.
