# yara-parser

`yara-parser` is a Go library for manipulating YARA rulesets.  Its key feature is that it uses the same grammar and lexer files as the original libyara to ensure that lexing and parsing work exactly like YARA.  The grammar and lexer files have been modified to fill Go data structures for ruleset manipulation instead of compiling rulesets for data matching.

Using `yara-parser`, one will be able to read YARA rulesets to programatically change metadata, rule names, rule modifiers, tags, strings, and more.

The ability to serialize rulesets to JSON for rule manipulation in other languages is provided with the `y2j` tool.  Similarly, `j2y` provides JSON-to-YARA conversion, but do see __Limitations__ below.

## Installation

For the following `go get` commands, if you experience any issues, they are likely due to outdated versions of Go.  The project uses features introduced in Go 1.10.  Installation should proceed normally after an update.

To install (or update) everything at once, the following command can be used:

`go get -u github.com/Northern-Lights/yara-parser/...`

### `y2j`: YARA to JSON

Use the following command to install the `y2j` command for converting YARA rulesets to JSON.

`go get -u github.com/Northern-Lights/yara-parser/cmd/y2j`

Of course, this will install `y2j` to `$GOPATH/bin`, so ensure that the latter is in your `$PATH`.

The grammar and lexer files are frozen so that building them with `goyacc` and `flexgo` are not necessary.

### `j2y`: JSON to YARA

Use the following command to install the `j2y` command for converting JSON to YARA rulesets.

`go get -u github.com/Northern-Lights/yara-parser/cmd/j2y`

### Grammar Library

Use the following command to install the grammar library for deserializing YARA rulesets without installing `y2j`.

`go get -u github.com/Northern-Lights/yara-parser/grammar`

## `y2j` Usage

Command line usage for `y2j` looks like the following:

```
$ y2j --help            
Usage of y2j: y2j [options] file.yar

options:
  -indent int
        Set number of indent spaces (default 2)
  -o string               
        JSON output file
```

In action, `y2j` would convert the following ruleset:

```yara
import "pe"
import "cuckoo"

include "other.yar"

global rule demo : tag1 {
meta:
    description = "This is a demo rule"
    version = 1
    production = false
    description = "because we can"
strings:
    $string = "this is a string" nocase wide
    $regex = /this is a regex/i ascii fullword
    $hex = { 01 23 45 67 89 ab cd ef [0-5] ?1 ?2 ?3 }
condition:
    $string or $regex or $hex
}
```

to this JSON output:

```json
{
   "file": "sample.yar",
   "imports": [
      "pe",
      "cuckoo"
   ],
   "includes": [
      "other.yar"
   ],
   "rules": [
      {
         "modifiers": {
            "global": true,
            "private": false
         },
         "identifier": "demo",
         "tags": [
            "tag1"
         ],
         "meta": [
            {
               "Key": "description",
               "Val": "This is a demo rule"
            },
            {
               "Key": "version",
               "Val": 1
            },
            {
               "Key": "production",
               "Val": false
            },
            {
               "Key": "description",
               "Val": "because we can"
            }
         ],
         "strings": [
            {
               "id": "$string",
               "type": 0,
               "text": "this is a string",
               "modifiers": {
                  "nocase": true,
                  "ascii": false,
                  "wide": true,
                  "fullword": false,
		  "xor": false,
                  "i": false,
                  "s": false
               }
            },
            {
               "id": "$regex",
               "type": 2,
               "text": "this is a regex",
               "modifiers": {
                  "nocase": false,
                  "ascii": true,
                  "wide": false,
                  "fullword": true,
		  "xor": false,
                  "i": true,
                  "s": false
               }
            },
            {
               "id": "$hex",
               "type": 1,
               "text": " 01 23 45 67 89 ab cd ef [0-5] ?1 ?2 ?3 ",
               "modifiers": {
                  "nocase": false,
                  "ascii": false,
                  "wide": false,
                  "fullword": false,
		  "xor": false,
                  "i": false,
                  "s": false
               }
            }
         ],
         "condition": "$string or $regex or $hex"
      }
   ]
}
```

Note that the string types are as follows:

| String type `int` code | Designation |
| - | - |
| 0 | string |
| 1 | hex pair bytes |
| 2 | regex |

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

## Development

The included Dockerfile will build an image suitable for producing the parser and lexer using goyacc and flexgo.  There is a `builder` target in the `Makefile` to help you quickly get started with this.  Run the following to build the builder image:

`make builder`

This will provide you with a Docker image called `yara-parser-builder`.

As you make changes to the grammar, you can then run `make grammar`.  The .go files will be output in the `grammar/` directory.

## Limitations

Currently, there are no guarantees with the library that modified rules will serialize back into a valid YARA ruleset.  For example, you can set `rule.Identifier = "123"`, but this would be invalid YARA.  Additionally, adding or removing strings may cause a condition to become invalid, and conditions are currently treated only as text.  Comments also cannot be retained.
