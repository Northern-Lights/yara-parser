// Code generated by goyacc -p xx -o /grammar/parser.go /grammar/grammar.y. DO NOT EDIT.

//line /grammar/grammar.y:31
package grammar

import __yyfmt__ "fmt"

//line /grammar/grammar.y:31
import (
	"fmt"
	"strings"

	"github.com/Northern-Lights/yara-parser/data"
)

var ParsedRuleset data.RuleSet

type regexPair struct {
	text string
	mods data.StringModifiers
}

//line /grammar/grammar.y:134
type xxSymType struct {
	yys int
	num data.Number
	s   string
	ss  []string

	rm  data.RuleModifiers
	m   data.Metas
	mp  data.Meta
	mps data.Metas
	mod data.StringModifiers
	reg regexPair
	ys  data.String
	yss data.Strings
	yr  data.Rule
}

const _END_OF_INCLUDED_FILE_ = 57346
const _DOT_DOT_ = 57347
const _RULE_ = 57348
const _PRIVATE_ = 57349
const _GLOBAL_ = 57350
const _META_ = 57351
const _STRINGS_ = 57352
const _CONDITION_ = 57353
const _IDENTIFIER_ = 57354
const _STRING_IDENTIFIER_ = 57355
const _STRING_COUNT_ = 57356
const _STRING_OFFSET_ = 57357
const _STRING_LENGTH_ = 57358
const _STRING_IDENTIFIER_WITH_WILDCARD_ = 57359
const _NUMBER_ = 57360
const _DOUBLE_ = 57361
const _INTEGER_FUNCTION_ = 57362
const _TEXT_STRING_ = 57363
const _HEX_STRING_ = 57364
const _REGEXP_ = 57365
const _ASCII_ = 57366
const _WIDE_ = 57367
const _XOR_ = 57368
const _NOCASE_ = 57369
const _FULLWORD_ = 57370
const _AT_ = 57371
const _FILESIZE_ = 57372
const _ENTRYPOINT_ = 57373
const _ALL_ = 57374
const _ANY_ = 57375
const _IN_ = 57376
const _OF_ = 57377
const _FOR_ = 57378
const _THEM_ = 57379
const _MATCHES_ = 57380
const _CONTAINS_ = 57381
const _IMPORT_ = 57382
const _TRUE_ = 57383
const _FALSE_ = 57384
const _LBRACE_ = 57385
const _RBRACE_ = 57386
const _INCLUDE_ = 57387
const _OR_ = 57388
const _AND_ = 57389
const _EQ_ = 57390
const _NEQ_ = 57391
const _LT_ = 57392
const _LE_ = 57393
const _GT_ = 57394
const _GE_ = 57395
const _SHIFT_LEFT_ = 57396
const _SHIFT_RIGHT_ = 57397
const _NOT_ = 57398
const UNARY_MINUS = 57399

var xxToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"_END_OF_INCLUDED_FILE_",
	"_DOT_DOT_",
	"_RULE_",
	"_PRIVATE_",
	"_GLOBAL_",
	"_META_",
	"_STRINGS_",
	"_CONDITION_",
	"_IDENTIFIER_",
	"_STRING_IDENTIFIER_",
	"_STRING_COUNT_",
	"_STRING_OFFSET_",
	"_STRING_LENGTH_",
	"_STRING_IDENTIFIER_WITH_WILDCARD_",
	"_NUMBER_",
	"_DOUBLE_",
	"_INTEGER_FUNCTION_",
	"_TEXT_STRING_",
	"_HEX_STRING_",
	"_REGEXP_",
	"_ASCII_",
	"_WIDE_",
	"_XOR_",
	"_NOCASE_",
	"_FULLWORD_",
	"_AT_",
	"_FILESIZE_",
	"_ENTRYPOINT_",
	"_ALL_",
	"_ANY_",
	"_IN_",
	"_OF_",
	"_FOR_",
	"_THEM_",
	"_MATCHES_",
	"_CONTAINS_",
	"_IMPORT_",
	"_TRUE_",
	"_FALSE_",
	"_LBRACE_",
	"_RBRACE_",
	"_INCLUDE_",
	"_OR_",
	"_AND_",
	"'|'",
	"'^'",
	"'&'",
	"_EQ_",
	"_NEQ_",
	"_LT_",
	"_LE_",
	"_GT_",
	"_GE_",
	"_SHIFT_LEFT_",
	"_SHIFT_RIGHT_",
	"'+'",
	"'-'",
	"'*'",
	"'\\\\'",
	"'%'",
	"_NOT_",
	"'~'",
	"UNARY_MINUS",
	"':'",
	"'='",
	"'('",
	"')'",
	"'.'",
	"'['",
	"']'",
	"','",
}
var xxStatenames = [...]string{}

const xxEofCode = 1
const xxErrCode = 2
const xxInitialStackSize = 16

//line /grammar/grammar.y:836

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	-2, 15,
	-1, 42,
	23, 34,
	-2, 32,
	-1, 52,
	35, 106,
	-2, 92,
	-1, 107,
	35, 106,
	-2, 92,
	-1, 159,
	70, 63,
	74, 63,
	-2, 66,
	-1, 196,
	70, 64,
	74, 64,
	-2, 66,
}

const xxPrivate = 57344

const xxLast = 390

var xxAct = [...]int{

	52, 193, 108, 141, 49, 147, 175, 111, 73, 53,
	64, 65, 66, 110, 61, 62, 60, 63, 215, 74,
	70, 203, 216, 189, 222, 204, 58, 59, 71, 72,
	174, 114, 54, 112, 113, 213, 150, 50, 51, 96,
	94, 95, 149, 48, 42, 212, 219, 210, 97, 98,
	89, 90, 91, 92, 93, 102, 68, 200, 107, 105,
	56, 69, 106, 197, 173, 57, 96, 94, 95, 115,
	116, 142, 109, 207, 148, 97, 98, 89, 90, 91,
	92, 93, 38, 123, 124, 125, 126, 127, 128, 129,
	130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
	140, 191, 122, 40, 146, 89, 90, 91, 92, 93,
	152, 153, 154, 79, 156, 81, 82, 80, 79, 159,
	80, 79, 28, 164, 165, 96, 94, 95, 87, 88,
	83, 85, 84, 86, 97, 98, 89, 90, 91, 92,
	93, 224, 26, 166, 221, 17, 39, 151, 18, 55,
	73, 168, 64, 65, 66, 167, 61, 62, 60, 63,
	104, 74, 74, 96, 94, 95, 80, 79, 58, 59,
	71, 72, 97, 98, 89, 90, 91, 92, 93, 143,
	196, 97, 98, 89, 90, 91, 92, 93, 172, 144,
	198, 91, 92, 93, 201, 35, 118, 99, 68, 218,
	77, 209, 100, 69, 101, 30, 211, 103, 44, 117,
	13, 43, 145, 217, 96, 94, 95, 220, 8, 205,
	78, 36, 223, 97, 98, 89, 90, 91, 92, 93,
	41, 46, 47, 155, 73, 37, 64, 65, 66, 171,
	61, 62, 60, 63, 31, 74, 96, 94, 95, 188,
	45, 23, 58, 59, 33, 97, 98, 89, 90, 91,
	92, 93, 96, 94, 95, 20, 185, 184, 206, 186,
	187, 97, 98, 89, 90, 91, 92, 93, 22, 14,
	25, 194, 68, 163, 170, 195, 192, 69, 96, 94,
	95, 103, 9, 11, 12, 169, 208, 97, 98, 89,
	90, 91, 92, 93, 81, 82, 121, 120, 202, 214,
	151, 199, 5, 190, 96, 94, 95, 87, 88, 83,
	85, 84, 86, 97, 98, 89, 90, 91, 92, 93,
	96, 94, 95, 158, 157, 67, 76, 75, 32, 97,
	98, 89, 90, 91, 92, 93, 94, 95, 7, 27,
	15, 1, 6, 4, 97, 98, 89, 90, 91, 92,
	93, 95, 181, 10, 119, 162, 161, 183, 97, 98,
	89, 90, 91, 92, 93, 160, 176, 34, 24, 178,
	177, 182, 179, 180, 29, 21, 19, 16, 2, 3,
}
var xxPact = [...]int{

	-1000, 308, -1000, -1000, 197, -1000, 286, 189, -1000, 267,
	-1000, -1000, -1000, -1000, -1000, 78, 105, 253, 269, 239,
	-1000, 270, 75, -1000, -1000, 55, 232, 243, 208, 232,
	-1000, 14, 102, 36, 208, -1000, -24, -1000, 190, -1000,
	-4, -1000, 178, -1000, -1000, 202, -1000, -1000, 120, -1000,
	-1000, -1000, 266, 168, 138, 125, -4, -4, -1000, -1000,
	3, -1000, -1000, -1000, -1000, -59, -65, -38, 222, 222,
	-1000, -1000, -1000, -1000, -1000, 188, 173, -1000, -1000, -1000,
	-1000, 139, 222, 222, 222, 222, 222, 222, 222, 222,
	222, 222, 222, 222, 222, 222, 222, 222, 222, 222,
	2, 177, 282, 222, 5, -1000, -34, 77, 120, 222,
	222, 222, 221, 222, -4, -1000, -1000, -1000, -1000, 276,
	-4, -4, -1000, 282, 282, 282, 282, 282, 282, 282,
	130, 130, -1000, -1000, -1000, 311, 124, 297, 46, 46,
	282, -1000, 222, -1000, 121, 5, 240, -1000, -1000, -1000,
	-1000, -1000, 214, 166, 115, -1000, -9, -40, -68, -1000,
	355, 242, -1000, -1000, -1000, 66, 18, -1000, 34, 268,
	-1000, -1000, -1000, -1000, -1000, -4, -1000, -1000, -1000, -1000,
	-1000, -1000, -6, -1000, -1000, -1000, -1000, -1000, -1000, 222,
	-12, -1000, -49, -1000, -1000, -1000, -1000, 201, 198, 6,
	222, -1000, -22, -1000, 268, -25, -1000, -1000, -52, 18,
	-4, -1000, -1000, 181, -23, -1000, 222, 74, -46, -4,
	282, -1000, -1000, 71, -1000,
}
var xxPgo = [...]int{

	0, 389, 388, 387, 386, 385, 384, 205, 378, 377,
	195, 376, 375, 367, 366, 365, 364, 363, 352, 351,
	350, 349, 338, 2, 337, 336, 335, 0, 334, 333,
	4, 20, 3, 149, 313, 311, 309, 5, 308, 307,
	306, 296, 295, 286, 1,
}
var xxR1 = [...]int{

	0, 19, 19, 19, 19, 19, 1, 20, 21, 2,
	5, 5, 8, 8, 22, 18, 18, 17, 17, 3,
	3, 4, 4, 6, 6, 7, 7, 7, 7, 7,
	9, 9, 24, 10, 25, 10, 10, 12, 12, 11,
	11, 11, 11, 11, 11, 11, 11, 14, 14, 13,
	13, 13, 13, 13, 16, 16, 15, 26, 26, 26,
	26, 28, 28, 29, 29, 31, 23, 30, 30, 30,
	30, 30, 30, 30, 30, 34, 36, 30, 38, 30,
	30, 30, 39, 30, 40, 30, 30, 30, 30, 30,
	30, 30, 30, 30, 35, 35, 32, 41, 41, 42,
	37, 37, 43, 43, 44, 44, 33, 33, 33, 27,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
	27, 27, 27, 27, 27,
}
var xxR2 = [...]int{

	0, 0, 2, 2, 3, 2, 2, 0, 0, 11,
	0, 3, 0, 3, 3, 0, 2, 1, 1, 0,
	2, 1, 2, 1, 2, 3, 3, 4, 3, 3,
	1, 2, 0, 5, 0, 5, 4, 0, 2, 1,
	1, 1, 1, 1, 1, 4, 6, 0, 2, 1,
	1, 1, 1, 1, 0, 2, 1, 1, 3, 4,
	4, 0, 1, 1, 3, 1, 1, 1, 1, 3,
	3, 1, 3, 3, 3, 0, 0, 11, 0, 9,
	3, 2, 0, 4, 0, 4, 3, 3, 3, 3,
	3, 3, 1, 3, 3, 1, 5, 1, 3, 0,
	4, 1, 1, 3, 1, 1, 1, 1, 1, 3,
	1, 1, 4, 1, 1, 1, 1, 4, 1, 4,
	1, 1, 2, 3, 3, 3, 3, 3, 3, 3,
	3, 2, 3, 3, 1,
}
var xxChk = [...]int{

	-1000, -19, -2, -1, 45, 4, -18, 40, 21, 6,
	-17, 7, 8, 21, 12, -20, -3, 67, 43, -4,
	12, -5, 9, 12, -8, 10, 67, -21, 67, -6,
	-7, 12, -22, 11, -9, -10, 13, -7, 68, 44,
	67, -10, 68, 21, 18, 60, 41, 42, -23, -30,
	41, 42, -27, 13, 36, -33, 64, 69, 30, 31,
	20, 18, 19, 21, 14, 15, 16, -26, 60, 65,
	-31, 32, 33, 12, 23, -24, -25, 22, 18, 47,
	46, 38, 39, 53, 55, 54, 56, 51, 52, 59,
	60, 61, 62, 63, 49, 50, 48, 57, 58, 29,
	34, -33, -27, 69, 35, -23, -30, -27, -23, 69,
	72, 72, 71, 72, 69, -27, -27, 21, 23, -16,
	-39, -40, -31, -27, -27, -27, -27, -27, -27, -27,
	-27, -27, -27, -27, -27, -27, -27, -27, -27, -27,
	-27, -32, 69, 2, 12, 35, -27, -37, 69, 37,
	70, 70, -27, -27, -27, 12, -27, -28, -29, -30,
	-12, -14, -15, 7, -23, -23, -27, 34, -37, -42,
	70, 73, 73, 73, 70, 74, -11, 25, 24, 27,
	28, 7, 26, -13, 25, 24, 27, 28, 7, 5,
	-34, 67, -43, -44, 13, 17, -30, 69, -27, -35,
	69, -32, -38, 70, 74, 18, 70, 67, -41, -27,
	69, -44, 70, 60, -36, 70, 74, -23, 18, 69,
	-27, 70, 70, -23, 70,
}
var xxDef = [...]int{

	1, -2, 2, 3, 0, 5, 0, 0, 4, 0,
	16, 17, 18, 6, 7, 19, 0, 0, 10, 20,
	21, 12, 0, 22, 8, 0, 0, 0, 0, 11,
	23, 0, 0, 0, 13, 30, 0, 24, 0, 9,
	0, 31, -2, 25, 26, 0, 28, 29, 14, 66,
	67, 68, -2, 71, 0, 0, 0, 0, 110, 111,
	0, 113, 114, 115, 116, 118, 120, 121, 0, 0,
	134, 107, 108, 57, 65, 0, 0, 54, 27, 82,
	84, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 106, 0, 0, 81, 66, -2, 0, 0,
	0, 0, 0, 0, 61, 122, 131, 37, 47, 36,
	0, 0, 69, 70, 86, 87, 88, 89, 90, 91,
	123, 124, 125, 126, 127, 128, 129, 130, 132, 133,
	72, 73, 0, 74, 0, 0, 0, 80, 99, 101,
	93, 109, 0, 0, 0, 58, 0, 0, 62, -2,
	33, 35, 55, 56, 83, 85, 0, 75, 0, 0,
	112, 117, 119, 59, 60, 0, 38, 39, 40, 41,
	42, 43, 44, 48, 49, 50, 51, 52, 53, 0,
	0, 78, 0, 102, 104, 105, -2, 0, 0, 0,
	0, 95, 0, 100, 0, 0, 96, 76, 0, 97,
	0, 103, 45, 0, 0, 94, 0, 0, 0, 0,
	98, 79, 46, 0, 77,
}
var xxTok1 = [...]int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 63, 50, 3,
	69, 70, 61, 59, 74, 60, 71, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 67, 3,
	3, 68, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 72, 62, 73, 49, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 48, 3, 65,
}
var xxTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 51, 52, 53, 54,
	55, 56, 57, 58, 64, 66,
}
var xxTok3 = [...]int{
	0,
}

var xxErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	xxDebug        = 0
	xxErrorVerbose = false
)

type xxLexer interface {
	Lex(lval *xxSymType) int
	Error(s string)
}

type xxParser interface {
	Parse(xxLexer) int
	Lookahead() int
}

type xxParserImpl struct {
	lval  xxSymType
	stack [xxInitialStackSize]xxSymType
	char  int
}

func (p *xxParserImpl) Lookahead() int {
	return p.char
}

func xxNewParser() xxParser {
	return &xxParserImpl{}
}

const xxFlag = -1000

func xxTokname(c int) string {
	if c >= 1 && c-1 < len(xxToknames) {
		if xxToknames[c-1] != "" {
			return xxToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func xxStatname(s int) string {
	if s >= 0 && s < len(xxStatenames) {
		if xxStatenames[s] != "" {
			return xxStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func xxErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !xxErrorVerbose {
		return "syntax error"
	}

	for _, e := range xxErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + xxTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := xxPact[state]
	for tok := TOKSTART; tok-1 < len(xxToknames); tok++ {
		if n := base + tok; n >= 0 && n < xxLast && xxChk[xxAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if xxDef[state] == -2 {
		i := 0
		for xxExca[i] != -1 || xxExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; xxExca[i] >= 0; i += 2 {
			tok := xxExca[i]
			if tok < TOKSTART || xxExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if xxExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += xxTokname(tok)
	}
	return res
}

func xxlex1(lex xxLexer, lval *xxSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = xxTok1[0]
		goto out
	}
	if char < len(xxTok1) {
		token = xxTok1[char]
		goto out
	}
	if char >= xxPrivate {
		if char < xxPrivate+len(xxTok2) {
			token = xxTok2[char-xxPrivate]
			goto out
		}
	}
	for i := 0; i < len(xxTok3); i += 2 {
		token = xxTok3[i+0]
		if token == char {
			token = xxTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = xxTok2[1] /* unknown char */
	}
	if xxDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", xxTokname(token), uint(char))
	}
	return char, token
}

func xxParse(xxlex xxLexer) int {
	return xxNewParser().Parse(xxlex)
}

func (xxrcvr *xxParserImpl) Parse(xxlex xxLexer) int {
	var xxn int
	var xxVAL xxSymType
	var xxDollar []xxSymType
	_ = xxDollar // silence set and not used
	xxS := xxrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	xxstate := 0
	xxrcvr.char = -1
	xxtoken := -1 // xxrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		xxstate = -1
		xxrcvr.char = -1
		xxtoken = -1
	}()
	xxp := -1
	goto xxstack

ret0:
	return 0

ret1:
	return 1

xxstack:
	/* put a state and value onto the stack */
	if xxDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", xxTokname(xxtoken), xxStatname(xxstate))
	}

	xxp++
	if xxp >= len(xxS) {
		nyys := make([]xxSymType, len(xxS)*2)
		copy(nyys, xxS)
		xxS = nyys
	}
	xxS[xxp] = xxVAL
	xxS[xxp].yys = xxstate

xxnewstate:
	xxn = xxPact[xxstate]
	if xxn <= xxFlag {
		goto xxdefault /* simple state */
	}
	if xxrcvr.char < 0 {
		xxrcvr.char, xxtoken = xxlex1(xxlex, &xxrcvr.lval)
	}
	xxn += xxtoken
	if xxn < 0 || xxn >= xxLast {
		goto xxdefault
	}
	xxn = xxAct[xxn]
	if xxChk[xxn] == xxtoken { /* valid shift */
		xxrcvr.char = -1
		xxtoken = -1
		xxVAL = xxrcvr.lval
		xxstate = xxn
		if Errflag > 0 {
			Errflag--
		}
		goto xxstack
	}

xxdefault:
	/* default state action */
	xxn = xxDef[xxstate]
	if xxn == -2 {
		if xxrcvr.char < 0 {
			xxrcvr.char, xxtoken = xxlex1(xxlex, &xxrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if xxExca[xi+0] == -1 && xxExca[xi+1] == xxstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			xxn = xxExca[xi+0]
			if xxn < 0 || xxn == xxtoken {
				break
			}
		}
		xxn = xxExca[xi+1]
		if xxn < 0 {
			goto ret0
		}
	}
	if xxn == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			xxlex.Error(xxErrorMessage(xxstate, xxtoken))
			Nerrs++
			if xxDebug >= 1 {
				__yyfmt__.Printf("%s", xxStatname(xxstate))
				__yyfmt__.Printf(" saw %s\n", xxTokname(xxtoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for xxp >= 0 {
				xxn = xxPact[xxS[xxp].yys] + xxErrCode
				if xxn >= 0 && xxn < xxLast {
					xxstate = xxAct[xxn] /* simulate a shift of "error" */
					if xxChk[xxstate] == xxErrCode {
						goto xxstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if xxDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", xxS[xxp].yys)
				}
				xxp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if xxDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", xxTokname(xxtoken))
			}
			if xxtoken == xxEofCode {
				goto ret1
			}
			xxrcvr.char = -1
			xxtoken = -1
			goto xxnewstate /* try again in the same state */
		}
	}

	/* reduction by production xxn */
	if xxDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", xxn, xxStatname(xxstate))
	}

	xxnt := xxn
	xxpt := xxp
	_ = xxpt // guard against "declared and not used"

	xxp -= xxR2[xxn]
	// xxp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if xxp+1 >= len(xxS) {
		nyys := make([]xxSymType, len(xxS)*2)
		copy(nyys, xxS)
		xxS = nyys
	}
	xxVAL = xxS[xxp+1]

	/* consult goto table to find next state */
	xxn = xxR1[xxn]
	xxg := xxPgo[xxn]
	xxj := xxg + xxS[xxp].yys + 1

	if xxj >= xxLast {
		xxstate = xxAct[xxg]
	} else {
		xxstate = xxAct[xxj]
		if xxChk[xxstate] != -xxn {
			xxstate = xxAct[xxg]
		}
	}
	// dummy call; replaced with literal code
	switch xxnt {

	case 2:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:155
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[2].yr)
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:158
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[2].s)
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:161
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[3].s)
		}
	case 5:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:164
		{
		}
	case 6:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:170
		{
			xxVAL.s = xxDollar[2].s
		}
	case 7:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:178
		{
			xxVAL.yr.Modifiers = xxDollar[1].rm
			xxVAL.yr.Identifier = xxDollar[3].s

			// Forbid duplicate rules
			for _, r := range ParsedRuleset.Rules {
				if xxDollar[3].s == r.Identifier {
					err := fmt.Errorf(`Duplicate rule "%s"`, xxDollar[3].s)
					panic(err)
				}
			}
		}
	case 8:
		xxDollar = xxS[xxpt-8 : xxpt+1]
//line /grammar/grammar.y:191
		{
			// $4 is the rule created in above action
			xxDollar[4].yr.Tags = xxDollar[5].ss

			// Forbid duplicate tags
			idx := make(map[string]struct{})
			for _, t := range xxDollar[5].ss {
				if _, had := idx[t]; had {
					msg := fmt.Sprintf(`grammar: Rule "%s" has duplicate tag "%s"`,
						xxDollar[4].yr.Identifier,
						t)
					panic(msg)
				}
				idx[t] = struct{}{}
			}

			xxDollar[4].yr.Meta = xxDollar[7].m

			xxDollar[4].yr.Strings = xxDollar[8].yss

			// Forbid duplicate string IDs, except `$` (anonymous)
			idx = make(map[string]struct{})
			for _, s := range xxDollar[8].yss {
				if s.ID == "$" {
					continue
				}
				if _, had := idx[s.ID]; had {
					msg := fmt.Sprintf(
						`grammar: Rule "%s" has duplicated string "%s"`,
						xxDollar[4].yr.Identifier,
						s.ID)
					panic(msg)
				}
				idx[s.ID] = struct{}{}
			}
		}
	case 9:
		xxDollar = xxS[xxpt-11 : xxpt+1]
//line /grammar/grammar.y:228
		{
			c := conditionBuilder.String()
			c = strings.TrimLeft(c, ":\n\r\t ")
			c = strings.TrimRight(c, "}\n\r\t ")
			xxDollar[4].yr.Condition = c
			xxVAL.yr = xxDollar[4].yr
		}
	case 10:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:240
		{

		}
	case 11:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:244
		{
			xxVAL.m = make(data.Metas, 0, len(xxDollar[3].mps))
			for _, mpair := range xxDollar[3].mps {
				// YARA is ok with duplicate keys; we follow suit
				xxVAL.m = append(xxVAL.m, mpair)
			}
		}
	case 12:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:256
		{
			xxVAL.yss = data.Strings{}
		}
	case 13:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:260
		{
			xxVAL.yss = xxDollar[3].yss
		}
	case 15:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:272
		{
			xxVAL.rm = data.RuleModifiers{}
		}
	case 16:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:273
		{
			xxVAL.rm.Private = xxVAL.rm.Private || xxDollar[2].rm.Private
			xxVAL.rm.Global = xxVAL.rm.Global || xxDollar[2].rm.Global
		}
	case 17:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:281
		{
			xxVAL.rm.Private = true
		}
	case 18:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:282
		{
			xxVAL.rm.Global = true
		}
	case 19:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:288
		{
			xxVAL.ss = []string{}
		}
	case 20:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:292
		{
			xxVAL.ss = xxDollar[2].ss
		}
	case 21:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:300
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 22:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:304
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[2].s)
		}
	case 23:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:312
		{
			xxVAL.mps = data.Metas{xxDollar[1].mp}
		}
	case 24:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:313
		{
			xxVAL.mps = append(xxVAL.mps, xxDollar[2].mp)
		}
	case 25:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:319
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].s}
		}
	case 26:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:323
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].num}
		}
	case 27:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:327
		{
			xxDollar[4].num.Val = -xxDollar[4].num.Val
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[4].num}
		}
	case 28:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:332
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, true}
		}
	case 29:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:336
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, false}
		}
	case 30:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:343
		{
			xxVAL.yss = data.Strings{xxDollar[1].ys}
		}
	case 31:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:344
		{
			xxVAL.yss = append(xxDollar[1].yss, xxDollar[2].ys)
		}
	case 32:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:350
		{
			xxVAL.ys.Type = data.TypeString
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 33:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:355
		{
			xxDollar[3].ys.Text = xxDollar[4].s
			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 34:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:362
		{
			xxVAL.ys.Type = data.TypeRegex
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 35:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:367
		{
			xxDollar[3].ys.Text = xxDollar[4].reg.text

			xxDollar[5].mod.I = xxDollar[4].reg.mods.I
			xxDollar[5].mod.S = xxDollar[4].reg.mods.S

			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 36:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:378
		{
			xxVAL.ys.Type = data.TypeHexString
			xxVAL.ys.ID = xxDollar[1].s
			xxVAL.ys.Text = xxDollar[3].s
			xxVAL.ys.Modifiers = xxDollar[4].mod
		}
	case 37:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:388
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 38:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:391
		{
			xorRange := xxDollar[2].mod.XorRange
			if xxDollar[1].mod.Xor {
				xorRange = xxDollar[1].mod.XorRange
			}

			xxVAL.mod = data.StringModifiers{
				Wide:     xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:    xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:   xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword: xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
				Private:  xxDollar[1].mod.Private || xxDollar[2].mod.Private,
				Xor:      xxDollar[1].mod.Xor || xxDollar[2].mod.Xor,
				XorRange: xorRange,
			}
		}
	case 39:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:411
		{
			xxVAL.mod.Wide = true
		}
	case 40:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:412
		{
			xxVAL.mod.ASCII = true
		}
	case 41:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:413
		{
			xxVAL.mod.Nocase = true
		}
	case 42:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:414
		{
			xxVAL.mod.Fullword = true
		}
	case 43:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:415
		{
			xxVAL.mod.Private = true
		}
	case 44:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:417
		{
			xxVAL.mod.Xor = true
		}
	case 45:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:421
		{
			if xxDollar[3].num.Val < 0 || xxDollar[3].num.Val > 255 {
				msg := fmt.Sprintf("XOR value must be in range between 0 and 255, provided value %d", xxDollar[3].num.Val)
				panic(msg)
			}

			xxVAL.mod.Xor = true
			xxVAL.mod.XorRange = data.XorRange{
				Min: xxDollar[3].num,
				Max: xxDollar[3].num,
			}
		}
	case 46:
		xxDollar = xxS[xxpt-6 : xxpt+1]
//line /grammar/grammar.y:434
		{
			if xxDollar[3].num.Val < 0 || xxDollar[5].num.Val > 255 || xxDollar[3].num.Val > xxDollar[5].num.Val {
				msg := fmt.Sprintf("XOR values must be in range between 0 and 255, provided values (%d - %d)", xxDollar[3].num.Val, xxDollar[5].num.Val)
				panic(msg)
			}

			xxVAL.mod.Xor = true
			xxVAL.mod.XorRange = data.XorRange{
				Min: xxDollar[3].num,
				Max: xxDollar[5].num,
			}
		}
	case 47:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:451
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 48:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:454
		{
			xxVAL.mod = data.StringModifiers{
				Wide:     xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:    xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:   xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword: xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
				Private:  xxDollar[1].mod.Private || xxDollar[2].mod.Private,
			}
		}
	case 49:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:467
		{
			xxVAL.mod.Wide = true
		}
	case 50:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:468
		{
			xxVAL.mod.ASCII = true
		}
	case 51:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:469
		{
			xxVAL.mod.Nocase = true
		}
	case 52:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:470
		{
			xxVAL.mod.Fullword = true
		}
	case 53:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:471
		{
			xxVAL.mod.Private = true
		}
	case 54:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:477
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 55:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:481
		{
			xxVAL.mod = data.StringModifiers{
				Private: xxDollar[1].mod.Private || xxDollar[2].mod.Private,
			}
		}
	case 56:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:490
		{
			xxVAL.mod.Private = true
		}
	case 57:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:496
		{

		}
	case 58:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:500
		{

		}
	case 59:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:504
		{

		}
	case 60:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:509
		{

		}
	case 61:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:516
		{
		}
	case 62:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:517
		{
		}
	case 63:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:522
		{

		}
	case 64:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:526
		{

		}
	case 65:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:534
		{

		}
	case 66:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:542
		{

		}
	case 67:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:549
		{

		}
	case 68:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:553
		{

		}
	case 69:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:557
		{

		}
	case 70:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:561
		{

		}
	case 71:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:565
		{

		}
	case 72:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:569
		{

		}
	case 73:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:573
		{

		}
	case 74:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:577
		{

		}
	case 75:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:581
		{

		}
	case 76:
		xxDollar = xxS[xxpt-7 : xxpt+1]
//line /grammar/grammar.y:585
		{

		}
	case 77:
		xxDollar = xxS[xxpt-11 : xxpt+1]
//line /grammar/grammar.y:589
		{

		}
	case 78:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:593
		{

		}
	case 79:
		xxDollar = xxS[xxpt-9 : xxpt+1]
//line /grammar/grammar.y:597
		{

		}
	case 80:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:601
		{

		}
	case 81:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:605
		{

		}
	case 82:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:609
		{

		}
	case 83:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:613
		{

		}
	case 84:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:617
		{

		}
	case 85:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:621
		{

		}
	case 86:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:625
		{

		}
	case 87:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:629
		{

		}
	case 88:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:633
		{

		}
	case 89:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:637
		{

		}
	case 90:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:641
		{

		}
	case 91:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:645
		{

		}
	case 92:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:649
		{

		}
	case 93:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:653
		{

		}
	case 94:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:660
		{
		}
	case 95:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:661
		{
		}
	case 96:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:667
		{

		}
	case 97:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:675
		{

		}
	case 98:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:679
		{

		}
	case 99:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:687
		{

		}
	case 101:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:692
		{

		}
	case 104:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:706
		{

		}
	case 105:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:710
		{

		}
	case 107:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:719
		{

		}
	case 108:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:723
		{

		}
	case 109:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:731
		{

		}
	case 110:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:735
		{

		}
	case 111:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:739
		{

		}
	case 112:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:743
		{

		}
	case 113:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:747
		{

		}
	case 114:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:751
		{

		}
	case 115:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:755
		{

		}
	case 116:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:759
		{

		}
	case 117:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:763
		{

		}
	case 118:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:767
		{

		}
	case 119:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:771
		{

		}
	case 120:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:775
		{

		}
	case 121:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:779
		{

		}
	case 122:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:783
		{

		}
	case 123:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:787
		{

		}
	case 124:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:791
		{

		}
	case 125:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:795
		{

		}
	case 126:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:799
		{

		}
	case 127:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:803
		{

		}
	case 128:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:807
		{

		}
	case 129:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:811
		{

		}
	case 130:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:815
		{

		}
	case 131:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:819
		{

		}
	case 132:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:823
		{

		}
	case 133:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:827
		{

		}
	case 134:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:831
		{

		}
	}
	goto xxstack /* stack new state and value */
}
