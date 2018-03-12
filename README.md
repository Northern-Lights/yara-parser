# yara-parser

`yara-parser` is a Go tool for manipulating YARA rulesets.  Its key feature is that it uses the same grammar and lexer files as the original libyara to ensure that no YARA feature is missed.

Currently, the tool is very much in an under-development state.

Using `yara-parser`, one will be able to read YARA rulesets to programatically change metadata, rule names, rule modifiers, tags, strings, and more.

The ability to serialize to JSON for rule manipulation in other languages will be provided, as well.

## Installation

The installation process/methodology is not yet complete.  Currently, there is a `Makefile` which will build the parser, lexer, and main application.  For this to work, the following are needed:

| Command | Source (`go get`) |
| - | - |
| `goyacc` | `golang.org/x/tools/cmd/goyacc` |
| `flexgo` | `github.com/pebbe/flexgo` (May require gcc/C build tools)|

In the future, the `parser.go` and `lexer.go` files will be frozen and included in the repository when releases are tagged.  This way, a user will not need to build these components.

## Usage

Sample usage looks like the following:

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

Currently, there are no guarantees with the library that modified rules will serialize back into a valid YARA ruleset.  For example, you can set `rule.Identifier = "123"`, but this would be invalid YARA.  Additionally, adding or removing strings may cause a condition to become invalid, and conditions are currently treated only as text.