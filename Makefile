parser:
	goyacc -p xx -o grammar/parser.go grammar/grammar.y

lexer:
	${GOPATH}/bin/flexgo -G -o grammar/lexer.go grammar/lexer.l

main:
	go build

all: parser lexer main

clean:
	rm grammar/lexer.go grammar/parser.go y.output yara-parser