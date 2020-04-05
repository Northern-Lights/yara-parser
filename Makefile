all: grammar y2j

builder:
	docker build -t yara-parser-builder .

grammar:
	docker run --rm -v ${PWD}/grammar:/grammar:Z yara-parser-builder bash -c 'flexgo -G -o /grammar/lexer.go /grammar/lexer.l && goyacc -p xx -o /grammar/parser.go /grammar/grammar.y'

j2y:
	go build github.com/Northern-Lights/yara-parser/cmd/j2y

y2j:
	go build github.com/Northern-Lights/yara-parser/cmd/y2j

release: parser lexer
	GOOS=linux go build -o y2j-linux github.com/Northern-Lights/yara-parser/cmd/y2j
	GOOS=darwin go build -o y2j-mac github.com/Northern-Lights/yara-parser/cmd/y2j
	GOOS=windows go build -o y2j.exe github.com/Northern-Lights/yara-parser/cmd/y2j

clean:
	rm grammar/lexer.go grammar/parser.go y.output y2j

.PHONY: grammar
