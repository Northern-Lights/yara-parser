//line grammar/grammar.y:2
package grammar

import __yyfmt__ "fmt"

//line grammar/grammar.y:2
import (
	"fmt"

	"github.com/Northern-Lights/yara-parser/data"
)

var ParsedRuleset data.RuleSet

type regexPair struct {
	text string
	mods data.StringModifiers
}

//line grammar/grammar.y:100
type xxSymType struct {
	yys int
	f64 float64
	i64 int64
	s   string
	ss  []string

	expr    data.Expression
	fexpr   data.ForExpression
	intset  data.IntegerSet
	m       data.Metas
	mod     data.StringModifiers
	mp      data.Meta
	mps     data.Metas
	r       data.Range
	reg     regexPair
	rm      data.RuleModifiers
	strset  data.StringSet
	strcnt  data.StringCount
	strlen  data.StringLength
	stroff  data.StringOffset
	unknown interface{}
	yr      data.Rule
	ys      data.String
	yss     data.Strings
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
const _STRING_LENGTH_ = 57356
const _STRING_OFFSET_ = 57357
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
	"_STRING_LENGTH_",
	"_STRING_OFFSET_",
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

//line grammar/grammar.y:717

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	-2, 14,
	-1, 41,
	22, 33,
	-2, 31,
	-1, 51,
	33, 85,
	-2, 72,
	-1, 106,
	33, 85,
	-2, 72,
	-1, 157,
	71, 48,
	72, 48,
	-2, 51,
	-1, 185,
	71, 49,
	72, 49,
	-2, 51,
}

const xxPrivate = 57344

const xxLast = 400

var xxAct = [...]int{

	51, 164, 48, 139, 145, 158, 79, 78, 194, 195,
	172, 72, 52, 63, 65, 64, 171, 60, 61, 59,
	62, 107, 73, 69, 79, 78, 183, 184, 57, 58,
	70, 71, 147, 200, 53, 95, 93, 94, 148, 49,
	50, 193, 190, 180, 96, 97, 88, 89, 90, 91,
	92, 199, 111, 112, 101, 113, 140, 106, 67, 105,
	192, 47, 55, 68, 108, 41, 110, 146, 114, 115,
	56, 109, 37, 187, 182, 39, 27, 104, 25, 16,
	79, 78, 121, 122, 123, 124, 125, 126, 127, 128,
	129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
	118, 119, 78, 144, 120, 90, 91, 92, 54, 150,
	151, 152, 38, 154, 80, 81, 157, 88, 89, 90,
	91, 92, 17, 159, 95, 93, 94, 86, 87, 82,
	84, 83, 85, 96, 97, 88, 89, 90, 91, 92,
	6, 160, 141, 34, 103, 4, 161, 73, 162, 149,
	72, 142, 63, 65, 64, 29, 60, 61, 59, 62,
	43, 73, 100, 42, 117, 181, 76, 57, 58, 70,
	71, 98, 116, 143, 12, 185, 99, 40, 7, 186,
	94, 189, 45, 46, 36, 77, 191, 96, 97, 88,
	89, 90, 91, 92, 165, 35, 198, 67, 166, 153,
	30, 44, 68, 22, 175, 174, 176, 177, 32, 102,
	19, 13, 196, 24, 72, 197, 63, 65, 64, 21,
	60, 61, 59, 62, 188, 73, 95, 93, 94, 156,
	155, 57, 58, 66, 75, 96, 97, 88, 89, 90,
	91, 92, 74, 95, 93, 94, 8, 10, 11, 26,
	14, 167, 96, 97, 88, 89, 90, 91, 92, 1,
	23, 67, 33, 2, 5, 9, 68, 28, 149, 95,
	93, 94, 173, 102, 20, 179, 31, 15, 96, 97,
	88, 89, 90, 91, 92, 95, 93, 94, 18, 163,
	3, 0, 170, 0, 96, 97, 88, 89, 90, 91,
	92, 95, 93, 94, 178, 0, 0, 0, 169, 0,
	96, 97, 88, 89, 90, 91, 92, 80, 81, 0,
	0, 0, 0, 0, 168, 0, 0, 95, 93, 94,
	86, 87, 82, 84, 83, 85, 96, 97, 88, 89,
	90, 91, 92, 0, 0, 0, 95, 93, 94, 0,
	0, 0, 0, 0, 0, 96, 97, 88, 89, 90,
	91, 92, 95, 93, 94, 0, 0, 0, 0, 0,
	0, 96, 97, 88, 89, 90, 91, 92, 93, 94,
	0, 0, 0, 0, 0, 0, 96, 97, 88, 89,
	90, 91, 92, 96, 97, 88, 89, 90, 91, 92,
}
var xxPact = [...]int{

	-1000, 102, -1000, -1000, 158, 241, 154, -1000, 200, -1000,
	-1000, -1000, -1000, -1000, 14, 81, 199, 211, 192, -1000,
	204, 13, -1000, -1000, 11, 189, 198, 183, 189, -1000,
	6, 70, 10, 183, -1000, -1, -1000, 143, -1000, 0,
	-1000, 145, -1000, -1000, 168, -1000, -1000, 36, -1000, -1000,
	-1000, 281, 144, 139, 111, 0, 0, -1000, -1000, -6,
	-1000, -1000, -1000, -1000, 3, -2, -15, 203, 203, -1000,
	-1000, -1000, -1000, -1000, 152, 142, -1000, -1000, 0, 0,
	125, 203, 203, 203, 203, 203, 203, 203, 203, 203,
	203, 203, 203, 203, 203, 203, 203, 203, 203, -14,
	140, 316, 203, -3, -1000, -33, 78, 36, 203, 203,
	203, 188, 203, 0, -1000, -1000, -1000, -1000, -1000, 57,
	-1000, 316, 316, 316, 316, 316, 316, 316, 46, 46,
	-1000, -1000, -1000, 132, 338, 331, 60, 60, 316, -1000,
	203, -1000, 114, -3, 197, -1000, 182, -1000, -1000, -1000,
	180, 255, 239, -1000, 223, -55, -62, -1000, 181, 181,
	300, -27, 9, -45, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, 0, -1000, -1000, -1000, -1000, -1000, 203, 8,
	203, -1000, -28, -1000, 182, -1000, -11, -29, -63, 300,
	0, -1000, -1000, 0, -1000, 203, -20, -38, 316, -1000,
	-1000,
}
var xxPgo = [...]int{

	0, 290, 1, 289, 288, 277, 21, 276, 2, 0,
	108, 275, 274, 272, 5, 155, 267, 3, 23, 265,
	264, 4, 263, 143, 262, 260, 259, 250, 249, 242,
	234, 233, 230, 229, 224,
}
var xxR1 = [...]int{

	0, 26, 26, 26, 26, 1, 27, 28, 22, 12,
	12, 25, 25, 7, 20, 20, 19, 19, 5, 5,
	4, 4, 16, 16, 15, 15, 15, 15, 15, 24,
	24, 29, 23, 30, 23, 23, 14, 14, 13, 13,
	13, 13, 31, 31, 31, 31, 32, 32, 33, 33,
	18, 6, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 11, 11, 17, 34, 34, 21,
	21, 3, 3, 2, 2, 10, 10, 10, 9, 9,
	9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	9, 9, 9, 9,
}
var xxR2 = [...]int{

	0, 0, 2, 2, 3, 2, 0, 0, 11, 0,
	3, 0, 3, 3, 0, 2, 1, 1, 0, 2,
	1, 2, 1, 2, 3, 3, 4, 3, 3, 1,
	2, 0, 5, 0, 5, 3, 0, 2, 1, 1,
	1, 1, 1, 3, 4, 4, 0, 1, 1, 3,
	1, 1, 1, 1, 3, 3, 1, 3, 3, 3,
	9, 8, 3, 2, 3, 3, 3, 3, 3, 3,
	3, 3, 1, 3, 3, 1, 5, 1, 3, 3,
	1, 1, 3, 1, 1, 1, 1, 1, 3, 1,
	1, 4, 1, 1, 1, 1, 4, 1, 4, 1,
	1, 2, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 3, 3, 1,
}
var xxChk = [...]int{

	-1000, -26, -22, -1, 43, -20, 38, 20, 5, -19,
	6, 7, 20, 11, -27, -5, 65, 41, -4, 11,
	-12, 8, 11, -25, 9, 65, -28, 65, -16, -15,
	11, -7, 10, -24, -23, 12, -15, 66, 42, 65,
	-23, 66, 20, 17, 58, 39, 40, -6, -8, 39,
	40, -9, 12, 34, -10, 62, 70, 28, 29, 19,
	17, 18, 20, 13, 15, 14, -31, 58, 63, -18,
	30, 31, 11, 22, -29, -30, 21, 17, 45, 44,
	36, 37, 51, 53, 52, 54, 49, 50, 57, 58,
	59, 60, 61, 47, 48, 46, 55, 56, 27, 32,
	-10, -9, 70, 33, -6, -8, -9, -6, 70, 68,
	68, 67, 68, 70, -9, -9, 20, 22, -6, -6,
	-18, -9, -9, -9, -9, -9, -9, -9, -9, -9,
	-9, -9, -9, -9, -9, -9, -9, -9, -9, -17,
	70, 2, 11, 33, -9, -21, 70, 35, 71, 71,
	-9, -9, -9, 11, -9, -32, -33, -8, -14, -14,
	-9, 32, -21, -3, -2, 12, 16, 71, 69, 69,
	69, 71, 72, -13, 24, 23, 25, 26, 4, -11,
	70, -17, 65, 71, 72, -8, -9, 65, -34, -9,
	70, -2, 71, 70, 71, 72, -6, -6, -9, 71,
	71,
}
var xxDef = [...]int{

	1, -2, 2, 3, 0, 0, 0, 4, 0, 15,
	16, 17, 5, 6, 18, 0, 0, 9, 19, 20,
	11, 0, 21, 7, 0, 0, 0, 0, 10, 22,
	0, 0, 0, 12, 29, 0, 23, 0, 8, 0,
	30, -2, 24, 25, 0, 27, 28, 13, 51, 52,
	53, -2, 56, 0, 0, 0, 0, 89, 90, 0,
	92, 93, 94, 95, 97, 99, 100, 0, 0, 113,
	86, 87, 42, 50, 0, 0, 35, 26, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 85, 0, 0, 63, 51, -2, 0, 0, 0,
	0, 0, 0, 46, 101, 110, 36, 36, 64, 65,
	54, 55, 66, 67, 68, 69, 70, 71, 102, 103,
	104, 105, 106, 107, 108, 109, 111, 112, 57, 58,
	0, 59, 0, 0, 0, 62, 0, 80, 73, 88,
	0, 0, 0, 43, 0, 0, 47, -2, 32, 34,
	0, 0, 0, 0, 81, 83, 84, 91, 96, 98,
	44, 45, 0, 37, 38, 39, 40, 41, 0, 0,
	0, 75, 0, 79, 0, -2, 0, 0, 0, 77,
	0, 82, 76, 0, 74, 0, 0, 0, 78, 61,
	60,
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
		//line grammar/grammar.y:131
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[2].yr)
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:134
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[2].s)
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:137
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[3].s)
		}
	case 5:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:145
		{
			xxVAL.s = xxDollar[2].s
		}
	case 6:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:153
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
		//line grammar/grammar.y:166
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
		//line grammar/grammar.y:203
		{
			xxDollar[4].yr.Condition = xxDollar[10].expr
			xxVAL.yr = xxDollar[4].yr
		}
	case 9:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:212
		{

		}
	case 10:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:216
		{
			xxVAL.m = make(data.Metas, 0, len(xxDollar[3].mps))
			for _, mpair := range xxDollar[3].mps {
				// YARA is ok with duplicate keys; we follow suit
				xxVAL.m = append(xxVAL.m, mpair)
			}
		}
	case 11:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:228
		{
			xxVAL.yss = data.Strings{}
		}
	case 12:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:232
		{
			xxVAL.yss = xxDollar[3].yss
		}
	case 13:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:240
		{
			xxVAL.expr = xxDollar[3].expr
		}
	case 14:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:247
		{
			xxVAL.rm = data.RuleModifiers{}
		}
	case 15:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:248
		{
			xxVAL.rm.Private = xxVAL.rm.Private || xxDollar[2].rm.Private
			xxVAL.rm.Global = xxVAL.rm.Global || xxDollar[2].rm.Global
		}
	case 16:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:256
		{
			xxVAL.rm.Private = true
		}
	case 17:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:257
		{
			xxVAL.rm.Global = true
		}
	case 18:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:263
		{
			xxVAL.ss = []string{}
		}
	case 19:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:267
		{
			xxVAL.ss = xxDollar[2].ss
		}
	case 20:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:275
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 21:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:279
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[2].s)
		}
	case 22:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:287
		{
			xxVAL.mps = data.Metas{xxDollar[1].mp}
		}
	case 23:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:288
		{
			xxVAL.mps = append(xxVAL.mps, xxDollar[2].mp)
		}
	case 24:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:294
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].s}
		}
	case 25:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:298
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].i64}
		}
	case 26:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:302
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, -xxDollar[4].i64}
		}
	case 27:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:306
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, true}
		}
	case 28:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:310
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, false}
		}
	case 29:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:317
		{
			xxVAL.yss = data.Strings{xxDollar[1].ys}
		}
	case 30:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:318
		{
			xxVAL.yss = append(xxDollar[1].yss, xxDollar[2].ys)
		}
	case 31:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:324
		{
			xxVAL.ys.Type = data.TypeString
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 32:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:329
		{
			xxDollar[3].ys.Text = xxDollar[4].s
			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 33:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:336
		{
			xxVAL.ys.Type = data.TypeRegex
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 34:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:341
		{
			xxDollar[3].ys.Text = xxDollar[4].reg.text

			xxDollar[5].mod.I = xxDollar[4].reg.mods.I
			xxDollar[5].mod.S = xxDollar[4].reg.mods.S

			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 35:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:352
		{
			xxVAL.ys.Type = data.TypeHexString
			xxVAL.ys.ID = xxDollar[1].s
			xxVAL.ys.Text = xxDollar[3].s
		}
	case 36:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:361
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 37:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:364
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
		//line grammar/grammar.y:376
		{
			xxVAL.mod.Wide = true
		}
	case 39:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:377
		{
			xxVAL.mod.ASCII = true
		}
	case 40:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:378
		{
			xxVAL.mod.Nocase = true
		}
	case 41:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:379
		{
			xxVAL.mod.Fullword = true
		}
	case 42:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:385
		{

		}
	case 43:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:389
		{

		}
	case 44:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:393
		{

		}
	case 45:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:398
		{

		}
	case 46:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:405
		{
		}
	case 47:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:406
		{
		}
	case 48:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:411
		{

		}
	case 49:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:415
		{

		}
	case 50:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:423
		{

		}
	case 51:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:431
		{
			xxVAL.expr = xxDollar[1].expr
		}
	case 52:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:438
		{
			xxVAL.expr = data.Expression{Left: true}
		}
	case 53:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:442
		{
			xxVAL.expr = data.Expression{Left: false}
		}
	case 54:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:446
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "matches", Right: xxDollar[3].reg}
		}
	case 55:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:450
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "contains", Right: xxDollar[3].expr}
		}
	case 56:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:454
		{
			xxVAL.expr = data.Expression{Left: data.TemporaryString{Identifier: xxDollar[1].s}}
		}
	case 57:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:458
		{
			xxVAL.expr = data.Expression{Left: data.TemporaryString{Identifier: xxDollar[1].s}, Operator: "at", Right: xxDollar[3].expr}
		}
	case 58:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:462
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].s, Operator: "in", Right: xxDollar[3].r}
		}
	case 59:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:466
		{
			// Unused: https://github.com/Northern-Lights/yara-parser/issues/12#issuecomment-376379471
			// tldr: the "error" is used to help recover from errors, but we don't need this
		}
	case 60:
		xxDollar = xxS[xxpt-9 : xxpt+1]
		//line grammar/grammar.y:471
		{
			xxVAL.expr = data.Expression{Left: data.ForInExpression{ForExpression: xxDollar[2].fexpr, Identifier: xxDollar[3].s, IntegerSet: xxDollar[5].intset, Boolean: xxDollar[8].expr}}
		}
	case 61:
		xxDollar = xxS[xxpt-8 : xxpt+1]
		//line grammar/grammar.y:475
		{
			xxVAL.expr = data.Expression{Left: data.ForOfExpression{ForExpression: xxDollar[2].fexpr, StringSet: xxDollar[4].strset, Boolean: xxDollar[7].expr}}
		}
	case 62:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:479
		{
			//$$ = data.Expression{Left: data.ForOfExpression{ForExpression: $2, StringSet: $4}}
		}
	case 63:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:483
		{
			xxVAL.expr = data.Expression{Left: xxDollar[2].expr, Operator: "not"}
		}
	case 64:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:487
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "and", Right: xxDollar[3].expr}
		}
	case 65:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:491
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "or", Right: xxDollar[3].expr}
		}
	case 66:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:495
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "<", Right: xxDollar[3].expr}
		}
	case 67:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:499
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: ">", Right: xxDollar[3].expr}
		}
	case 68:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:503
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "<=", Right: xxDollar[3].expr}
		}
	case 69:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:507
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: ">=", Right: xxDollar[3].expr}
		}
	case 70:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:511
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "==", Right: xxDollar[3].expr}
		}
	case 71:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:515
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "!=", Right: xxDollar[3].expr}
		}
	case 72:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:519
		{
			xxVAL.expr = xxDollar[1].expr
		}
	case 73:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:523
		{
			xxVAL.expr = xxDollar[2].expr
		}
	case 74:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:530
		{
		}
	case 75:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:531
		{
		}
	case 76:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:537
		{
			xxVAL.r = data.Range{From: xxDollar[2].expr, To: xxDollar[4].expr}
		}
	case 77:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:545
		{

		}
	case 78:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:549
		{

		}
	case 79:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:557
		{
			xxVAL.strset = data.StringSet{Array: xxDollar[2].ss}
		}
	case 80:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:561
		{
			xxVAL.strset = data.StringSet{Keyword: data.Keyword{Name: "them"}}
		}
	case 81:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:569
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 82:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:573
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[3].s)
		}
	case 83:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:581
		{
			xxVAL.s = xxDollar[1].s
		}
	case 84:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:585
		{
			xxVAL.s = xxDollar[1].s
		}
	case 85:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:593
		{
			xxVAL.fexpr = data.ForExpression{Expression: xxDollar[1].expr}
		}
	case 86:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:597
		{
			xxVAL.fexpr = data.ForExpression{Keyword: data.Keyword{Name: "all"}}
		}
	case 87:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:601
		{
			xxVAL.fexpr = data.ForExpression{Keyword: data.Keyword{Name: "any"}}
		}
	case 88:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:609
		{
			xxVAL.expr = xxDollar[2].expr
		}
	case 89:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:613
		{
			xxVAL.expr = data.Expression{Left: data.Keyword{Name: "filesize"}}
		}
	case 90:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:617
		{
			xxVAL.expr = data.Expression{Left: data.Keyword{Name: "entrypoint"}}
		}
	case 91:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:621
		{
			// TODO: document custom operator
			xxVAL.expr = data.Expression{Left: xxDollar[1].s, Operator: "integer_function", Right: xxDollar[3].expr}
		}
	case 92:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:626
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].i64}
		}
	case 93:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:630
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].f64}
		}
	case 94:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:634
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].s}
		}
	case 95:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:638
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].strcnt}
		}
	case 96:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:642
		{
			xxDollar[1].stroff.Index = xxDollar[3].expr
			xxVAL.expr = data.Expression{Left: xxDollar[1].stroff}
		}
	case 97:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:647
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].stroff}
		}
	case 98:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:651
		{
			xxDollar[1].strlen.Index = xxDollar[3].expr
			xxVAL.expr = data.Expression{Left: xxDollar[1].strlen}
		}
	case 99:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:656
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].strlen}
		}
	case 100:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:660
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].s}
		}
	case 101:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:664
		{
			xxVAL.expr = data.Expression{Left: xxDollar[2].expr, Operator: "unary-minus"}
		}
	case 102:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:668
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "+", Right: xxDollar[3].expr}
		}
	case 103:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:672
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "-", Right: xxDollar[3].expr}
		}
	case 104:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:676
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "*", Right: xxDollar[3].expr}
		}
	case 105:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:680
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "\\", Right: xxDollar[3].expr}
		}
	case 106:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:684
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "%", Right: xxDollar[3].expr}
		}
	case 107:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:688
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "^", Right: xxDollar[3].expr}
		}
	case 108:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:692
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "&", Right: xxDollar[3].expr}
		}
	case 109:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:696
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "|", Right: xxDollar[3].expr}
		}
	case 110:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:700
		{
			xxVAL.expr = data.Expression{Left: xxDollar[2].expr, Operator: "~"}
		}
	case 111:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:704
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: "<<", Right: xxDollar[3].expr}
		}
	case 112:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:708
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].expr, Operator: ">>", Right: xxDollar[3].expr}
		}
	case 113:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:712
		{
			xxVAL.expr = data.Expression{Left: xxDollar[1].reg}
		}
	}
	goto xxstack /* stack new state and value */
}
