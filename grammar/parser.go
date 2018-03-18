//line grammar/grammar.y:2
package grammar

import __yyfmt__ "fmt"

//line grammar/grammar.y:2
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

//line grammar/grammar.y:95
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
const _LPAREN_ = 57383
const _RPAREN_ = 57384
const _LBRACE_ = 57385
const _RBRACE_ = 57386
const _LBRACKET_ = 57387
const _RBRACKET_ = 57388
const _COLON_ = 57389
const _DOT_ = 57390
const _EQUAL_SIGN_ = 57391
const _COMMA_ = 57392
const _INCLUDE_ = 57393
const _OR_ = 57394
const _AND_ = 57395
const _PIPE_ = 57396
const _CARAT_ = 57397
const _AMP_ = 57398
const _EQ_ = 57399
const _NEQ_ = 57400
const _LT_ = 57401
const _LE_ = 57402
const _GT_ = 57403
const _GE_ = 57404
const _SHIFT_LEFT_ = 57405
const _SHIFT_RIGHT_ = 57406
const _PLUS_ = 57407
const _MINUS_ = 57408
const _ASTERISK_ = 57409
const _BACKSLASH_ = 57410
const _PERCENT_ = 57411
const _NOT_ = 57412
const _TILDE_ = 57413
const UNARY_MINUS = 57414

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
	"_LPAREN_",
	"_RPAREN_",
	"_LBRACE_",
	"_RBRACE_",
	"_LBRACKET_",
	"_RBRACKET_",
	"_COLON_",
	"_DOT_",
	"_EQUAL_SIGN_",
	"_COMMA_",
	"_INCLUDE_",
	"_OR_",
	"_AND_",
	"_PIPE_",
	"_CARAT_",
	"_AMP_",
	"_EQ_",
	"_NEQ_",
	"_LT_",
	"_LE_",
	"_GT_",
	"_GE_",
	"_SHIFT_LEFT_",
	"_SHIFT_RIGHT_",
	"_PLUS_",
	"_MINUS_",
	"_ASTERISK_",
	"_BACKSLASH_",
	"_PERCENT_",
	"_NOT_",
	"_TILDE_",
	"UNARY_MINUS",
}
var xxStatenames = [...]string{}

const xxEofCode = 1
const xxErrCode = 2
const xxInitialStackSize = 16

//line grammar/grammar.y:691

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	5, 17,
	6, 17,
	7, 17,
	-2, 0,
	-1, 46,
	22, 36,
	-2, 34,
	-1, 56,
	33, 93,
	-2, 79,
	-1, 111,
	33, 93,
	-2, 79,
	-1, 162,
	52, 54,
	53, 54,
	-2, 51,
	-1, 189,
	52, 54,
	53, 54,
	-2, 52,
}

const xxPrivate = 57344

const xxLast = 385

var xxAct = [...]int{

	56, 186, 112, 53, 150, 163, 95, 96, 97, 77,
	57, 68, 69, 70, 83, 65, 66, 64, 67, 74,
	78, 93, 94, 95, 96, 97, 62, 63, 75, 76,
	195, 46, 58, 84, 83, 201, 176, 54, 55, 61,
	42, 193, 100, 98, 99, 84, 83, 52, 59, 194,
	199, 101, 102, 93, 94, 95, 96, 97, 171, 106,
	84, 83, 111, 109, 72, 110, 184, 44, 60, 73,
	100, 98, 99, 119, 120, 32, 30, 21, 115, 101,
	102, 93, 94, 95, 96, 97, 114, 126, 127, 128,
	129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
	139, 140, 141, 142, 143, 125, 7, 105, 149, 5,
	182, 85, 86, 43, 155, 156, 157, 154, 159, 11,
	22, 175, 162, 153, 197, 191, 165, 166, 164, 100,
	98, 99, 91, 92, 87, 89, 88, 90, 101, 102,
	93, 94, 95, 96, 97, 7, 167, 34, 77, 145,
	68, 69, 70, 169, 65, 66, 64, 67, 4, 78,
	100, 98, 99, 113, 108, 62, 63, 75, 76, 101,
	102, 93, 94, 95, 96, 97, 98, 99, 107, 168,
	189, 41, 78, 190, 101, 102, 93, 94, 95, 96,
	97, 85, 86, 122, 196, 118, 198, 81, 152, 117,
	200, 103, 116, 72, 151, 39, 104, 121, 73, 100,
	98, 99, 91, 92, 87, 89, 88, 90, 101, 102,
	93, 94, 95, 96, 97, 77, 146, 68, 69, 70,
	174, 65, 66, 64, 67, 147, 78, 17, 100, 98,
	99, 16, 62, 63, 45, 8, 82, 101, 102, 93,
	94, 95, 96, 97, 173, 107, 40, 148, 179, 178,
	180, 181, 100, 98, 99, 187, 158, 35, 27, 188,
	24, 101, 102, 93, 94, 95, 96, 97, 172, 18,
	72, 37, 29, 26, 185, 73, 100, 98, 99, 170,
	154, 12, 14, 15, 124, 101, 102, 93, 94, 95,
	96, 97, 100, 98, 99, 123, 192, 183, 144, 161,
	160, 101, 102, 93, 94, 95, 96, 97, 100, 98,
	99, 71, 80, 79, 36, 31, 19, 101, 102, 93,
	94, 95, 96, 97, 99, 48, 1, 6, 47, 13,
	177, 101, 102, 93, 94, 95, 96, 97, 101, 102,
	93, 94, 95, 96, 97, 2, 3, 50, 51, 38,
	28, 9, 10, 33, 25, 23, 20, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 49,
}
var xxPact = [...]int{

	-1000, 107, -1000, -1000, 225, 68, 286, 221, -1000, -1000,
	-1000, 217, 268, -1000, -1000, -1000, -1000, -1000, -1000, 30,
	77, 259, 275, 257, -1000, 273, 29, -1000, -1000, 28,
	256, 271, 244, 256, -1000, -9, 69, 20, 244, -1000,
	-18, -1000, 318, -1000, -2, -1000, 176, -1000, -1000, 229,
	-1000, -1000, -19, -1000, -1000, -1000, 155, 174, 137, 131,
	-2, -2, -1000, -1000, 122, -1000, -1000, -1000, -1000, 41,
	33, 154, 214, 214, -1000, -1000, -1000, -1000, -1000, 187,
	171, -1000, -1000, -1000, -1000, 160, 214, 214, 214, 214,
	214, 214, 214, 214, 214, 214, 214, 214, 214, 214,
	214, 214, 214, 214, 108, 224, 264, 214, 163, -1000,
	81, 75, -19, 214, 214, 214, 255, 214, -2, -1000,
	-1000, -1000, -1000, -2, -2, -1000, 264, 264, 264, 264,
	264, 264, 264, -61, -61, -1000, -1000, -1000, 278, 285,
	121, -44, -44, 264, -1000, 214, -1000, 147, 163, 248,
	-1000, -1000, -1000, -1000, -1000, 16, 232, 208, -1000, 184,
	79, -14, -1000, 235, 235, -1000, -39, 106, -1000, 19,
	253, -1000, -1000, -1000, -1000, -1000, -2, -1000, -1000, -1000,
	-1000, -1000, 214, 84, -1000, -1, -1000, -1000, -1000, -1000,
	-12, -2, 83, -1000, 253, -1000, 8, -2, -1000, -1000,
	-7, -1000,
}
var xxPgo = [...]int{

	0, 356, 355, 366, 365, 364, 363, 147, 360, 359,
	205, 340, 5, 339, 337, 336, 326, 325, 324, 2,
	323, 322, 321, 0, 310, 309, 3, 19, 308, 48,
	307, 4, 306, 305, 294, 294, 294, 289, 284, 1,
}
var xxR1 = [...]int{

	0, 15, 15, 15, 15, 15, 15, 15, 1, 16,
	17, 2, 5, 5, 8, 8, 18, 14, 14, 13,
	13, 3, 3, 4, 4, 6, 6, 7, 7, 7,
	7, 7, 9, 9, 20, 10, 21, 10, 10, 12,
	12, 11, 11, 11, 11, 22, 22, 22, 22, 24,
	24, 25, 25, 27, 19, 26, 26, 26, 26, 26,
	26, 26, 26, 30, 26, 32, 26, 26, 26, 33,
	26, 34, 26, 26, 26, 26, 26, 26, 26, 26,
	26, 35, 35, 28, 36, 36, 37, 31, 31, 38,
	38, 39, 39, 29, 29, 29, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
	23, 23,
}
var xxR2 = [...]int{

	0, 0, 2, 2, 3, 3, 3, 4, 2, 0,
	0, 11, 0, 3, 0, 3, 3, 0, 2, 1,
	1, 0, 2, 1, 2, 1, 2, 3, 3, 4,
	3, 3, 1, 2, 0, 5, 0, 5, 3, 0,
	2, 1, 1, 1, 1, 1, 3, 4, 4, 0,
	1, 1, 3, 1, 1, 1, 1, 3, 3, 1,
	3, 3, 3, 0, 8, 0, 9, 3, 2, 0,
	4, 0, 4, 3, 3, 3, 3, 3, 3, 1,
	3, 3, 1, 5, 1, 3, 0, 4, 1, 1,
	3, 1, 1, 1, 1, 1, 3, 1, 1, 4,
	1, 1, 1, 1, 4, 1, 4, 1, 1, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 2, 3,
	3, 1,
}
var xxChk = [...]int{

	-1000, -15, -2, -1, 51, 2, -14, 38, 20, -2,
	-1, 51, 5, -13, 6, 7, 20, 20, 11, -16,
	-3, 47, 43, -4, 11, -5, 8, 11, -8, 9,
	47, -17, 47, -6, -7, 11, -18, 10, -9, -10,
	12, -7, 49, 44, 47, -10, 49, 20, 17, 66,
	39, 40, -19, -26, 39, 40, -23, 12, 34, -29,
	70, 41, 28, 29, 19, 17, 18, 20, 13, 14,
	15, -22, 66, 71, -27, 30, 31, 11, 22, -20,
	-21, 21, 17, 53, 52, 36, 37, 59, 61, 60,
	62, 57, 58, 65, 66, 67, 68, 69, 55, 56,
	54, 63, 64, 27, 32, -29, -23, 41, 33, -19,
	-26, -23, -19, 41, 45, 45, 48, 45, 41, -23,
	-23, 20, 22, -33, -34, -27, -23, -23, -23, -23,
	-23, -23, -23, -23, -23, -23, -23, -23, -23, -23,
	-23, -23, -23, -23, -28, 41, 2, 11, 33, -23,
	-31, 41, 35, 42, 42, -23, -23, -23, 11, -23,
	-24, -25, -26, -12, -12, -19, -19, -23, 32, -31,
	-37, 42, 46, 46, 46, 42, 50, -11, 24, 23,
	25, 26, 4, -30, 47, -38, -39, 12, 16, -26,
	-23, 41, -32, 42, 50, 42, -19, 41, -39, 42,
	-19, 42,
}
var xxDef = [...]int{

	1, -2, 2, 3, 0, 17, 0, 0, 4, 5,
	6, 0, 0, 18, 19, 20, 8, 7, 9, 21,
	0, 0, 12, 22, 23, 14, 0, 24, 10, 0,
	0, 0, 0, 13, 25, 0, 0, 0, 15, 32,
	0, 26, 0, 11, 0, 33, -2, 27, 28, 0,
	30, 31, 16, 54, 55, 56, -2, 59, 0, 0,
	0, 0, 97, 98, 0, 100, 101, 102, 103, 105,
	107, 108, 0, 0, 121, 94, 95, 45, 53, 0,
	0, 38, 29, 69, 71, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 93, 0, 0, 68,
	54, -2, 0, 0, 0, 0, 0, 0, 49, 109,
	118, 39, 39, 0, 0, 57, 58, 73, 74, 75,
	76, 77, 78, 110, 111, 112, 113, 114, 115, 116,
	117, 119, 120, 60, 61, 0, 62, 0, 0, 0,
	67, 86, 88, 80, 96, 0, 0, 0, 46, 0,
	0, 50, -2, 35, 37, 70, 72, 0, 63, 0,
	0, 99, 104, 106, 47, 48, 0, 40, 41, 42,
	43, 44, 0, 0, 65, 0, 89, 91, 92, -2,
	0, 0, 0, 87, 0, 83, 0, 0, 90, 64,
	0, 66,
}
var xxTok1 = [...]int{

	1,
}
var xxTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
	62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
	72,
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
		//line grammar/grammar.y:116
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[2].yr)
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:119
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[2].s)
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:122
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[3].s)
		}
	case 5:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:125
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[3].yr)
		}
	case 6:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:128
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[3].s)
		}
	case 7:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:131
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[4].s)
		}
	case 8:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:139
		{
			xxVAL.s = xxDollar[2].s
		}
	case 9:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:147
		{
			xxVAL.yr.Modifiers = xxDollar[1].rm
			xxVAL.yr.Identifier = xxDollar[3].s
		}
	case 10:
		xxDollar = xxS[xxpt-8 : xxpt+1]
		//line grammar/grammar.y:152
		{
			// $4 is the rule created in above action
			xxDollar[4].yr.Tags = xxDollar[5].ss
			xxDollar[4].yr.Meta = xxDollar[7].m
			xxDollar[4].yr.Strings = xxDollar[8].yss

			// Forbid duplicate string IDs, except `$` (anonymous)
			idx := make(map[string]struct{})
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
	case 11:
		xxDollar = xxS[xxpt-11 : xxpt+1]
		//line grammar/grammar.y:175
		{
			c := conditionBuilder.String()
			c = strings.TrimLeft(c, ":\n\r\t ")
			c = strings.TrimRight(c, "}\n\r\t ")
			xxDollar[4].yr.Condition = c
			xxVAL.yr = xxDollar[4].yr
		}
	case 12:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:187
		{

		}
	case 13:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:191
		{
			xxVAL.m = make(data.Metas, 0, len(xxDollar[3].mps))
			for _, mpair := range xxDollar[3].mps {
				// YARA is ok with duplicate keys; we follow suit
				xxVAL.m = append(xxVAL.m, mpair)
			}
		}
	case 14:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:203
		{
			xxVAL.yss = data.Strings{}
		}
	case 15:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:207
		{
			xxVAL.yss = xxDollar[3].yss
		}
	case 17:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:219
		{
			xxVAL.rm = data.RuleModifiers{}
		}
	case 18:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:220
		{
			xxVAL.rm.Private = xxVAL.rm.Private || xxDollar[2].rm.Private
			xxVAL.rm.Global = xxVAL.rm.Global || xxDollar[2].rm.Global
		}
	case 19:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:228
		{
			xxVAL.rm.Private = true
		}
	case 20:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:229
		{
			xxVAL.rm.Global = true
		}
	case 21:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:235
		{
			xxVAL.ss = []string{}
		}
	case 22:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:239
		{
			xxVAL.ss = xxDollar[2].ss
		}
	case 23:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:247
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 24:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:251
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[2].s)
		}
	case 25:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:259
		{
			xxVAL.mps = data.Metas{xxDollar[1].mp}
		}
	case 26:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:260
		{
			xxVAL.mps = append(xxVAL.mps, xxDollar[2].mp)
		}
	case 27:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:266
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].s}
		}
	case 28:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:270
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].i64}
		}
	case 29:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:274
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, -xxDollar[4].i64}
		}
	case 30:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:278
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, true}
		}
	case 31:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:282
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, false}
		}
	case 32:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:289
		{
			xxVAL.yss = data.Strings{xxDollar[1].ys}
		}
	case 33:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:290
		{
			xxVAL.yss = append(xxDollar[1].yss, xxDollar[2].ys)
		}
	case 34:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:296
		{
			xxVAL.ys.Type = data.TypeString
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 35:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:301
		{
			xxDollar[3].ys.Text = xxDollar[4].s
			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 36:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:308
		{
			xxVAL.ys.Type = data.TypeRegex
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 37:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:313
		{
			xxDollar[3].ys.Text = xxDollar[4].reg.text

			xxDollar[5].mod.I = xxDollar[4].reg.mods.I
			xxDollar[5].mod.S = xxDollar[4].reg.mods.S

			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 38:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:324
		{
			xxVAL.ys.Type = data.TypeHexString
			xxVAL.ys.ID = xxDollar[1].s
			xxVAL.ys.Text = xxDollar[3].s
		}
	case 39:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:333
		{
		}
	case 40:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:334
		{
			xxVAL.mod = data.StringModifiers{
				Wide:     xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:    xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:   xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword: xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
			}
		}
	case 41:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:346
		{
			xxVAL.mod.Wide = true
		}
	case 42:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:347
		{
			xxVAL.mod.ASCII = true
		}
	case 43:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:348
		{
			xxVAL.mod.Nocase = true
		}
	case 44:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:349
		{
			xxVAL.mod.Fullword = true
		}
	case 45:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:355
		{

		}
	case 46:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:359
		{

		}
	case 47:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:363
		{

		}
	case 48:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:368
		{

		}
	case 49:
		xxDollar = xxS[xxpt-0 : xxpt+1]
		//line grammar/grammar.y:375
		{
		}
	case 50:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:376
		{
		}
	case 51:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:381
		{

		}
	case 52:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:385
		{

		}
	case 53:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:393
		{

		}
	case 54:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:401
		{

		}
	case 55:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:408
		{

		}
	case 56:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:412
		{

		}
	case 57:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:416
		{

		}
	case 58:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:420
		{

		}
	case 59:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:424
		{

		}
	case 60:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:428
		{

		}
	case 61:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:432
		{

		}
	case 62:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:436
		{

		}
	case 63:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:440
		{

		}
	case 64:
		xxDollar = xxS[xxpt-8 : xxpt+1]
		//line grammar/grammar.y:444
		{

		}
	case 65:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:448
		{

		}
	case 66:
		xxDollar = xxS[xxpt-9 : xxpt+1]
		//line grammar/grammar.y:452
		{

		}
	case 67:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:456
		{

		}
	case 68:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:460
		{

		}
	case 69:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:464
		{

		}
	case 70:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:468
		{

		}
	case 71:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:472
		{

		}
	case 72:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:476
		{

		}
	case 73:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:480
		{

		}
	case 74:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:484
		{

		}
	case 75:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:488
		{

		}
	case 76:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:492
		{

		}
	case 77:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:496
		{

		}
	case 78:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:500
		{

		}
	case 79:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:504
		{

		}
	case 80:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:508
		{

		}
	case 81:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:515
		{
		}
	case 82:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:516
		{
		}
	case 83:
		xxDollar = xxS[xxpt-5 : xxpt+1]
		//line grammar/grammar.y:522
		{

		}
	case 84:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:530
		{

		}
	case 85:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:534
		{

		}
	case 86:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:542
		{

		}
	case 88:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:547
		{

		}
	case 91:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:561
		{

		}
	case 92:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:565
		{

		}
	case 94:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:574
		{

		}
	case 95:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:578
		{

		}
	case 96:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:586
		{

		}
	case 97:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:590
		{

		}
	case 98:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:594
		{

		}
	case 99:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:598
		{

		}
	case 100:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:602
		{

		}
	case 101:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:606
		{

		}
	case 102:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:610
		{

		}
	case 103:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:614
		{

		}
	case 104:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:618
		{

		}
	case 105:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:622
		{

		}
	case 106:
		xxDollar = xxS[xxpt-4 : xxpt+1]
		//line grammar/grammar.y:626
		{

		}
	case 107:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:630
		{

		}
	case 108:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:634
		{

		}
	case 109:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:638
		{

		}
	case 110:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:642
		{

		}
	case 111:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:646
		{

		}
	case 112:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:650
		{

		}
	case 113:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:654
		{

		}
	case 114:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:658
		{

		}
	case 115:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:662
		{

		}
	case 116:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:666
		{

		}
	case 117:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:670
		{

		}
	case 118:
		xxDollar = xxS[xxpt-2 : xxpt+1]
		//line grammar/grammar.y:674
		{

		}
	case 119:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:678
		{

		}
	case 120:
		xxDollar = xxS[xxpt-3 : xxpt+1]
		//line grammar/grammar.y:682
		{

		}
	case 121:
		xxDollar = xxS[xxpt-1 : xxpt+1]
		//line grammar/grammar.y:686
		{

		}
	}
	goto xxstack /* stack new state and value */
}
