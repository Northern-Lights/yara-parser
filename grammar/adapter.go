// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package grammar

import (
	"fmt"
	"io"
	"sync"

	"github.com/Northern-Lights/yara-parser/data"
)

var parserLock sync.Mutex

var errParser error

func init() {
	xxErrorVerbose = true
}

// Parse takes an input source and an output and initiates parsing
func Parse(input io.Reader, output io.Writer) (rs data.RuleSet, err error) {
	parserLock.Lock()
	defer parserLock.Unlock()
	defer recoverParse(&err)

	// "Reset" the global ParsedRuleset
	ParsedRuleset = data.RuleSet{}

	lexer := goyaccLexerAdapter{
		scanner: *NewScanner(),
	}
	lexer.scanner.In = input
	lexer.scanner.Out = output

	result := xxParse(&lexer)
	if result != 0 {

		err = fmt.Errorf(`Parser result: "%d" %s`, result, errParser)
	}

	rs = ParsedRuleset

	return
}

// goyaccLexerAdapter fits the flexgo lexer ("Scanner") into goyacc
type goyaccLexerAdapter struct {
	scanner Scanner
}

// Lex provides the interface expected by the goyacc parser.
// Allows flexgo's lval to be used by goyacc via the global yylval
func (l *goyaccLexerAdapter) Lex(lval *xxSymType) int {
	yylval = lval
	return l.scanner.Lex().(int)
}

// Error satisfies the interface expected by the goyacc parser
func (l *goyaccLexerAdapter) Error(e string) {
	errParser = fmt.Errorf(`grammar: lexical error @%d: "%s"`,
		l.scanner.Lineno, e)
}
