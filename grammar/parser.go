//line grammar/grammar.y:2
package grammar

import __yyfmt__ "fmt"

//line grammar/grammar.y:2
import (
	"fmt"
	"strings"

	"github.com/CapacitorSet/yara-parser/data"
)

var ParsedRuleset data.RuleSet

type regexPair struct {
	text string
	mods data.StringModifiers
}

//line grammar/grammar.y:89
type xxSymType struct {
	yys int
	i64 int64
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

const _DOT_DOT_ = 57346
const _RULE_ = 57347
const _PRIVATE_ = 57348
const _GLOBAL_ = 57349
const _META_ = 57350
const _STRINGS_ = 57351
const _CONDITION_ = 57352
const _IDENTIFIER_ = 57353
const _STRING_IDENTIFIER_ = 57354
const _STRING_COUNT_ = 57355
const _STRING_OFFSET_ = 57356
const _STRING_LENGTH_ = 57357
const _STRING_IDENTIFIER_WITH_WILDCARD_ = 57358
const _NUMBER_ = 57359
const _DOUBLE_ = 57360
const _INTEGER_FUNCTION_ = 57361
const _TEXT_STRING_ = 57362
const _HEX_STRING_ = 57363
const _REGEXP_ = 57364
const _ASCII_ = 57365
const _WIDE_ = 57366
const _NOCASE_ = 57367
const _FULLWORD_ = 57368
const _AT_ = 57369
const _FILESIZE_ = 57370
const _ENTRYPOINT_ = 57371
const _ALL_ = 57372
const _ANY_ = 57373
const _IN_ = 57374
const _OF_ = 57375
const _FOR_ = 57376
const _THEM_ = 57377
const _MATCHES_ = 57378
const _CONTAINS_ = 57379
const _IMPORT_ = 57380
const _TRUE_ = 57381
const _FALSE_ = 57382
const _LBRACE_ = 57383
const _RBRACE_ = 57384
const _INCLUDE_ = 57385
const _OR_ = 57386
const _AND_ = 57387
const _EQ_ = 57388
const _NEQ_ = 57389
const _LT_ = 57390
const _LE_ = 57391
const _GT_ = 57392
const _GE_ = 57393
const _SHIFT_LEFT_ = 57394
const _SHIFT_RIGHT_ = 57395
const _NOT_ = 57396
const UNARY_MINUS = 57397

var xxToknames = [...]string{
	"$end",
	"error",
	"$unk",
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
	"'.'",
	"'['",
	"']'",
	"'('",
	"')'",
	"','",
}
var xxStatenames = [...]string{}

const xxEofCode = 1
const xxErrCode = 2
const xxInitialStackSize = 16

//line grammar/grammar.y:704

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	-2, 14,
	-1, 41,
	22, 33,
	-2, 31,
	-1, 51,
	33, 91,
	-2, 77,
	-1, 106,
	33, 91,
	-2, 77,
	-1, 157,
	71, 48,
	72, 48,
	-2, 51,
	-1, 184,
	71, 49,
	72, 49,
	-2, 51,
}

const xxPrivate = 57344

const xxLast = 402

var xxAct = [...]int{

	51, 181, 107, 139, 48, 145, 158, 171, 72, 52,
	63, 64, 65, 170, 60, 61, 59, 62, 148, 73,
	69, 199, 200, 190, 191, 57, 58, 70, 71, 79,
	78, 53, 111, 112, 202, 113, 49, 50, 95, 93,
	94, 147, 47, 79, 78, 196, 187, 96, 97, 88,
	89, 90, 91, 92, 101, 67, 206, 106, 104, 55,
	68, 105, 41, 192, 140, 108, 110, 56, 114, 115,
	204, 109, 78, 37, 193, 179, 146, 88, 89, 90,
	91, 92, 121, 122, 123, 124, 125, 126, 127, 128,
	129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
	39, 120, 27, 144, 25, 16, 90, 91, 92, 150,
	151, 152, 54, 154, 38, 80, 81, 17, 157, 79,
	78, 160, 161, 103, 159, 95, 93, 94, 86, 87,
	82, 84, 83, 85, 96, 97, 88, 89, 90, 91,
	92, 162, 96, 97, 88, 89, 90, 91, 92, 164,
	149, 72, 34, 63, 64, 65, 141, 60, 61, 59,
	62, 43, 73, 163, 42, 142, 100, 6, 57, 58,
	70, 71, 4, 73, 98, 29, 184, 117, 185, 99,
	76, 116, 188, 45, 46, 12, 40, 143, 195, 174,
	173, 175, 176, 197, 7, 77, 182, 35, 67, 201,
	183, 203, 44, 68, 36, 205, 153, 30, 22, 72,
	102, 63, 64, 65, 19, 60, 61, 59, 62, 13,
	73, 95, 93, 94, 32, 24, 57, 58, 21, 180,
	96, 97, 88, 89, 90, 91, 92, 165, 95, 93,
	94, 8, 10, 11, 194, 119, 166, 96, 97, 88,
	89, 90, 91, 92, 118, 189, 67, 198, 186, 178,
	156, 68, 155, 149, 95, 93, 94, 66, 102, 75,
	74, 31, 26, 96, 97, 88, 89, 90, 91, 92,
	95, 93, 94, 14, 1, 5, 9, 169, 172, 96,
	97, 88, 89, 90, 91, 92, 95, 93, 94, 177,
	33, 23, 28, 168, 20, 96, 97, 88, 89, 90,
	91, 92, 80, 81, 18, 15, 2, 3, 0, 167,
	0, 0, 95, 93, 94, 86, 87, 82, 84, 83,
	85, 96, 97, 88, 89, 90, 91, 92, 0, 0,
	0, 95, 93, 94, 0, 0, 0, 0, 0, 0,
	96, 97, 88, 89, 90, 91, 92, 95, 93, 94,
	0, 0, 0, 0, 0, 0, 96, 97, 88, 89,
	90, 91, 92, 93, 94, 0, 0, 0, 0, 0,
	0, 96, 97, 88, 89, 90, 91, 92, 94, 0,
	0, 0, 0, 0, 0, 96, 97, 88, 89, 90,
	91, 92,
}
var xxPact = [...]int{

	-1000, 129, -1000, -1000, 174, 236, 165, -1000, 208, -1000,
	-1000, -1000, -1000, -1000, 40, 76, 203, 220, 197, -1000,
	216, 39, -1000, -1000, 37, 196, 214, 185, 196, -1000,
	7, 72, 35, 185, -1000, -4, -1000, 144, -1000, -3,
	-1000, 159, -1000, -1000, 178, -1000, -1000, 75, -1000, -1000,
	-1000, 276, 147, 140, 90, -3, -3, -1000, -1000, -5,
	-1000, -1000, -1000, -1000, 3, -2, -35, 198, 198, -1000,
	-1000, -1000, -1000, -1000, 161, 155, -1000, -1000, -1000, -1000,
	151, 198, 198, 198, 198, 198, 198, 198, 198, 198,
	198, 198, 198, 198, 198, 198, 198, 198, 198, -6,
	154, 311, 198, 6, -1000, -53, 79, 75, 198, 198,
	198, 195, 198, -3, -1000, -1000, -1000, -1000, -3, -3,
	-1000, 311, 311, 311, 311, 311, 311, 311, 47, 47,
	-1000, -1000, -1000, 340, 87, 326, 20, 20, 311, -1000,
	198, -1000, 131, 6, 192, -1000, -1000, -1000, -1000, -1000,
	175, 250, 234, -1000, 218, -58, -65, -1000, 166, 166,
	-1000, 27, 295, -1000, 10, 184, -1000, -1000, -1000, -1000,
	-1000, -3, -1000, -1000, -1000, -1000, -1000, 198, -24, -1000,
	-48, -1000, -1000, -1000, -1000, -8, 9, 198, -1000, -25,
	-1000, 184, -1000, -1000, -50, 295, -3, -1000, -36, -1000,
	198, -1, -3, 311, -1000, -15, -1000,
}
var xxPgo = [...]int{

	0, 317, 316, 315, 314, 304, 302, 175, 301, 300,
	152, 288, 6, 286, 285, 284, 283, 272, 271, 2,
	270, 269, 267, 0, 262, 260, 4, 20, 3, 112,
	259, 258, 257, 5, 255, 254, 245, 244, 237, 229,
	1,
}
var xxR1 = [...]int{

	0, 15, 15, 15, 15, 1, 16, 17, 2, 5,
	5, 8, 8, 18, 14, 14, 13, 13, 3, 3,
	4, 4, 6, 6, 7, 7, 7, 7, 7, 9,
	9, 20, 10, 21, 10, 10, 12, 12, 11, 11,
	11, 11, 22, 22, 22, 22, 24, 24, 25, 25,
	27, 19, 26, 26, 26, 26, 26, 26, 26, 26,
	30, 32, 26, 34, 26, 26, 26, 35, 26, 36,
	26, 26, 26, 26, 26, 26, 26, 26, 26, 31,
	31, 28, 37, 37, 38, 33, 33, 39, 39, 40,
	40, 29, 29, 29, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
}
var xxR2 = [...]int{

	0, 0, 2, 2, 3, 2, 0, 0, 11, 0,
	3, 0, 3, 3, 0, 2, 1, 1, 0, 2,
	1, 2, 1, 2, 3, 3, 4, 3, 3, 1,
	2, 0, 5, 0, 5, 3, 0, 2, 1, 1,
	1, 1, 1, 3, 4, 4, 0, 1, 1, 3,
	1, 1, 1, 1, 3, 3, 1, 3, 3, 3,
	0, 0, 11, 0, 9, 3, 2, 0, 4, 0,
	4, 3, 3, 3, 3, 3, 3, 1, 3, 3,
	1, 5, 1, 3, 0, 4, 1, 1, 3, 1,
	1, 1, 1, 1, 3, 1, 1, 4, 1, 1,
	1, 1, 4, 1, 4, 1, 1, 2, 3, 3,
	3, 3, 3, 3, 3, 3, 2, 3, 3, 1,
}
var xxChk = [...]int{

	-1000, -15, -2, -1, 43, -14, 38, 20, 5, -13,
	6, 7, 20, 11, -16, -3, 65, 41, -4, 11,
	-5, 8, 11, -8, 9, 65, -17, 65, -6, -7,
	11, -18, 10, -9, -10, 12, -7, 66, 42, 65,
	-10, 66, 20, 17, 58, 39, 40, -19, -26, 39,
	40, -23, 12, 34, -29, 62, 70, 28, 29, 19,
	17, 18, 20, 13, 14, 15, -22, 58, 63, -27,
	30, 31, 11, 22, -20, -21, 21, 17, 45, 44,
	36, 37, 51, 53, 52, 54, 49, 50, 57, 58,
	59, 60, 61, 47, 48, 46, 55, 56, 27, 32,
	-29, -23, 70, 33, -19, -26, -23, -19, 70, 68,
	68, 67, 68, 70, -23, -23, 20, 22, -35, -36,
	-27, -23, -23, -23, -23, -23, -23, -23, -23, -23,
	-23, -23, -23, -23, -23, -23, -23, -23, -23, -28,
	70, 2, 11, 33, -23, -33, 70, 35, 71, 71,
	-23, -23, -23, 11, -23, -24, -25, -26, -12, -12,
	-19, -19, -23, 32, -33, -38, 71, 69, 69, 69,
	71, 72, -11, 24, 23, 25, 26, 4, -30, 65,
	-39, -40, 12, 16, -26, -23, -31, 70, -28, -34,
	71, 72, 71, 65, -37, -23, 70, -40, -32, 71,
	72, -19, 70, -23, 71, -19, 71,
}
var xxDef = [...]int{

	1, -2, 2, 3, 0, 0, 0, 4, 0, 15,
	16, 17, 5, 6, 18, 0, 0, 9, 19, 20,
	11, 0, 21, 7, 0, 0, 0, 0, 10, 22,
	0, 0, 0, 12, 29, 0, 23, 0, 8, 0,
	30, -2, 24, 25, 0, 27, 28, 13, 51, 52,
	53, -2, 56, 0, 0, 0, 0, 95, 96, 0,
	98, 99, 100, 101, 103, 105, 106, 0, 0, 119,
	92, 93, 42, 50, 0, 0, 35, 26, 67, 69,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 91, 0, 0, 66, 51, -2, 0, 0, 0,
	0, 0, 0, 46, 107, 116, 36, 36, 0, 0,
	54, 55, 71, 72, 73, 74, 75, 76, 108, 109,
	110, 111, 112, 113, 114, 115, 117, 118, 57, 58,
	0, 59, 0, 0, 0, 65, 84, 86, 78, 94,
	0, 0, 0, 43, 0, 0, 47, -2, 32, 34,
	68, 70, 0, 60, 0, 0, 97, 102, 104, 44,
	45, 0, 37, 38, 39, 40, 41, 0, 0, 63,
	0, 87, 89, 90, -2, 0, 0, 0, 80, 0,
	85, 0, 81, 61, 0, 82, 0, 88, 0, 79,
	0, 0, 0, 83, 64, 0, 62,
}
var xxTok1 = [...]int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 61, 48, 3,
	70, 71, 59, 57, 72, 58, 67, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 65, 3,
	3, 66, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 68, 60, 69, 47, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 46, 3, 63,
}
var xxTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 49, 50, 51, 52, 53, 54,
	55, 56, 62, 64,
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
		//line grammar/grammar.y:110
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[2].yr)
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:113
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[2].s)
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:116
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[3].s)
		}
	case 5:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:124
		{
			xxVAL.s = xxDollar[2].s
		}
	case 6:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:132
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
	case 7:
		xxDollar = xxS[xxpt-8 : xxpt+1]
		//line grammar/grammar.y:145
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
	case 8:
		xxDollar = xxS[xxpt-11 : xxpt+1]
		//line grammar/grammar.y:182
		{
			c := conditionBuilder.String()
			c = strings.TrimLeft(c, ":\n\r\t ")
			c = strings.TrimRight(c, "}\n\r\t ")
			xxDollar[4].yr.Condition = c
			xxVAL.yr = xxDollar[4].yr
		}
	case 9:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:194
		{

		}
	case 10:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:198
		{
			xxVAL.m = make(data.Metas, 0, len(xxDollar[3].mps))
			for _, mpair := range xxDollar[3].mps {
				// YARA is ok with duplicate keys; we follow suit
				xxVAL.m = append(xxVAL.m, mpair)
			}
		}
	case 11:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:210
		{
			xxVAL.yss = data.Strings{}
		}
	case 12:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:214
		{
			xxVAL.yss = xxDollar[3].yss
		}
	case 14:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:226
		{
			xxVAL.rm = data.RuleModifiers{}
		}
	case 15:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:227
		{
			xxVAL.rm.Private = xxVAL.rm.Private || xxDollar[2].rm.Private
			xxVAL.rm.Global = xxVAL.rm.Global || xxDollar[2].rm.Global
		}
	case 16:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:235
		{
			xxVAL.rm.Private = true
		}
	case 17:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:236
		{
			xxVAL.rm.Global = true
		}
	case 18:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:242
		{
			xxVAL.ss = []string{}
		}
	case 19:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:246
		{
			xxVAL.ss = xxDollar[2].ss
		}
	case 20:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:254
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 21:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:258
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[2].s)
		}
	case 22:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:266
		{
			xxVAL.mps = data.Metas{xxDollar[1].mp}
		}
	case 23:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:267
		{
			xxVAL.mps = append(xxVAL.mps, xxDollar[2].mp)
		}
	case 24:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:273
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].s}
		}
	case 25:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:277
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].i64}
		}
	case 26:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:281
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, -xxDollar[4].i64}
		}
	case 27:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:285
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, true}
		}
	case 28:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:289
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, false}
		}
	case 29:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:296
		{
			xxVAL.yss = data.Strings{xxDollar[1].ys}
		}
	case 30:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:297
		{
			xxVAL.yss = append(xxDollar[1].yss, xxDollar[2].ys)
		}
	case 31:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:303
		{
			xxVAL.ys.Type = data.TypeString
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 32:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:308
		{
			xxDollar[3].ys.Text = xxDollar[4].s
			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 33:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:315
		{
			xxVAL.ys.Type = data.TypeRegex
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 34:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:320
		{
			xxDollar[3].ys.Text = xxDollar[4].reg.text

			xxDollar[5].mod.I = xxDollar[4].reg.mods.I
			xxDollar[5].mod.S = xxDollar[4].reg.mods.S

			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 35:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:331
		{
			xxVAL.ys.Type = data.TypeHexString
			xxVAL.ys.ID = xxDollar[1].s
			xxVAL.ys.Text = xxDollar[3].s
		}
	case 36:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:340
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 37:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:343
		{
			xxVAL.mod = data.StringModifiers{
				Wide:     xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:    xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:   xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword: xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
			}
		}
	case 38:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:355
		{
			xxVAL.mod.Wide = true
		}
	case 39:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:356
		{
			xxVAL.mod.ASCII = true
		}
	case 40:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:357
		{
			xxVAL.mod.Nocase = true
		}
	case 41:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:358
		{
			xxVAL.mod.Fullword = true
		}
	case 42:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:364
		{

		}
	case 43:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:368
		{

		}
	case 44:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:372
		{

		}
	case 45:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:377
		{

		}
	case 46:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:384
		{
		}
	case 47:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:385
		{
		}
	case 48:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:390
		{

		}
	case 49:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:394
		{

		}
	case 50:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:402
		{

		}
	case 51:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:410
		{

		}
	case 52:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:417
		{

		}
	case 53:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:421
		{

		}
	case 54:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:425
		{

		}
	case 55:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:429
		{

		}
	case 56:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:433
		{

		}
	case 57:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:437
		{

		}
	case 58:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:441
		{

		}
	case 59:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:445
		{

		}
	case 60:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:449
		{

		}
	case 61:
		xxDollar = xxS[xxpt-7 : xxpt+1]
		//line grammar/grammar.y:453
		{

		}
	case 62:
		xxDollar = xxS[xxpt-11 : xxpt+1]
		//line grammar/grammar.y:457
		{

		}
	case 63:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:461
		{

		}
	case 64:
		xxDollar = xxS[xxpt-9 : xxpt+1]
		//line grammar/grammar.y:465
		{

		}
	case 65:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:469
		{

		}
	case 66:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:473
		{

		}
	case 67:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:477
		{

		}
	case 68:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:481
		{

		}
	case 69:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:485
		{

		}
	case 70:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:489
		{

		}
	case 71:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:493
		{

		}
	case 72:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:497
		{

		}
	case 73:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:501
		{

		}
	case 74:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:505
		{

		}
	case 75:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:509
		{

		}
	case 76:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:513
		{

		}
	case 77:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:517
		{

		}
	case 78:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:521
		{

		}
	case 79:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:528
		{
		}
	case 80:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:529
		{
		}
	case 81:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:535
		{

		}
	case 82:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:543
		{

		}
	case 83:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:547
		{

		}
	case 84:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:555
		{

		}
	case 86:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:560
		{

		}
	case 89:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:574
		{

		}
	case 90:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:578
		{

		}
	case 92:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:587
		{

		}
	case 93:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:591
		{

		}
	case 94:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:599
		{

		}
	case 95:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:603
		{

		}
	case 96:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:607
		{

		}
	case 97:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:611
		{

		}
	case 98:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:615
		{

		}
	case 99:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:619
		{

		}
	case 100:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:623
		{

		}
	case 101:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:627
		{

		}
	case 102:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:631
		{

		}
	case 103:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:635
		{

		}
	case 104:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:639
		{

		}
	case 105:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:643
		{

		}
	case 106:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:647
		{

		}
	case 107:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:651
		{

		}
	case 108:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:655
		{

		}
	case 109:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:659
		{

		}
	case 110:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:663
		{

		}
	case 111:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:667
		{

		}
	case 112:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:671
		{

		}
	case 113:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:675
		{

		}
	case 114:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:679
		{

		}
	case 115:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:683
		{

		}
	case 116:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:687
		{

		}
	case 117:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:691
		{

		}
	case 118:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:695
		{

		}
	case 119:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:699
		{

		}
	}
	goto xxstack /* stack new state and value */
}
