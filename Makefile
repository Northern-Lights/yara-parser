all: parser lexer y2j

parser:
	goyacc -p xx -o grammar/parser.go grammar/grammar.y

lexer:
	${GOPATH}/bin/flexgo -G -o grammar/lexer.go grammar/lexer.l

y2j:
	go build github.com/Northern-Lights/yara-parser/cmd/y2j

clean:
	rm grammar/lexer.go grammar/parser.go y.output y2j
