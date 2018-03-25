all: parser lexer

parser:
	goyacc -p xx -o grammar/parser.go grammar/grammar.y

lexer:
	${GOPATH}/bin/flexgo -G -o grammar/lexer.go grammar/lexer.l

release: parser lexer

clean:
	rm grammar/lexer.go grammar/parser.go y.output
