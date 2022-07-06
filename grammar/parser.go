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

//line /grammar/grammar.y:143
type xxSymType struct {
	yys int
	i64 data.Int
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
const _BASE64_ = 57369
const _BASE64_WIDE_ = 57370
const _NOCASE_ = 57371
const _FULLWORD_ = 57372
const _AT_ = 57373
const _FILESIZE_ = 57374
const _ENTRYPOINT_ = 57375
const _ALL_ = 57376
const _ANY_ = 57377
const _NONE_ = 57378
const _IN_ = 57379
const _OF_ = 57380
const _FOR_ = 57381
const _THEM_ = 57382
const _MATCHES_ = 57383
const _CONTAINS_ = 57384
const _STARTSWITH_ = 57385
const _ENDSWITH_ = 57386
const _ICONTAINS_ = 57387
const _ISTARTSWITH_ = 57388
const _IENDSWITH_ = 57389
const _IEQUALS_ = 57390
const _IMPORT_ = 57391
const _TRUE_ = 57392
const _FALSE_ = 57393
const _LBRACE_ = 57394
const _RBRACE_ = 57395
const _INCLUDE_ = 57396
const _OR_ = 57397
const _AND_ = 57398
const _EQ_ = 57399
const _NEQ_ = 57400
const _LT_ = 57401
const _LE_ = 57402
const _GT_ = 57403
const _GE_ = 57404
const _SHIFT_LEFT_ = 57405
const _SHIFT_RIGHT_ = 57406
const _NOT_ = 57407
const _DEFINED_ = 57408
const UNARY_MINUS = 57409

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
	"_BASE64_",
	"_BASE64_WIDE_",
	"_NOCASE_",
	"_FULLWORD_",
	"_AT_",
	"_FILESIZE_",
	"_ENTRYPOINT_",
	"_ALL_",
	"_ANY_",
	"_NONE_",
	"_IN_",
	"_OF_",
	"_FOR_",
	"_THEM_",
	"_MATCHES_",
	"_CONTAINS_",
	"_STARTSWITH_",
	"_ENDSWITH_",
	"_ICONTAINS_",
	"_ISTARTSWITH_",
	"_IENDSWITH_",
	"_IEQUALS_",
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
	"_DEFINED_",
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

//line /grammar/grammar.y:1019

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	-2, 15,
	-1, 42,
	23, 34,
	-2, 32,
	-1, 52,
	38, 129,
	-2, 103,
	-1, 117,
	38, 129,
	-2, 103,
	-1, 182,
	80, 67,
	84, 67,
	-2, 70,
	-1, 240,
	80, 68,
	84, 68,
	-2, 70,
}

const xxPrivate = 57344

const xxLast = 470

var xxAct = [...]int{

	52, 234, 201, 118, 49, 159, 68, 168, 169, 84,
	85, 87, 89, 86, 88, 90, 91, 256, 248, 237,
	193, 257, 249, 238, 208, 105, 103, 104, 97, 98,
	93, 95, 94, 96, 106, 107, 99, 100, 101, 102,
	92, 122, 71, 125, 48, 123, 124, 121, 173, 83,
	82, 260, 265, 262, 261, 111, 207, 73, 172, 117,
	114, 115, 259, 116, 243, 242, 241, 194, 103, 104,
	126, 127, 171, 171, 255, 160, 106, 107, 99, 100,
	101, 102, 166, 225, 119, 42, 134, 135, 136, 137,
	138, 139, 140, 142, 143, 144, 145, 146, 147, 148,
	149, 150, 151, 152, 153, 154, 155, 156, 157, 158,
	82, 197, 170, 167, 38, 192, 40, 28, 26, 17,
	174, 239, 176, 177, 229, 179, 175, 133, 83, 82,
	182, 105, 103, 104, 39, 187, 188, 101, 102, 166,
	106, 107, 99, 100, 101, 102, 166, 55, 18, 189,
	190, 99, 100, 101, 102, 166, 113, 206, 198, 161,
	120, 191, 108, 35, 105, 103, 104, 142, 109, 165,
	74, 30, 196, 106, 107, 99, 100, 101, 102, 166,
	253, 129, 5, 80, 252, 73, 53, 65, 66, 67,
	205, 62, 63, 61, 64, 164, 74, 128, 41, 230,
	227, 37, 110, 13, 232, 59, 60, 75, 76, 77,
	8, 264, 54, 240, 106, 107, 99, 100, 101, 102,
	166, 251, 81, 50, 51, 244, 104, 7, 36, 245,
	247, 202, 4, 106, 107, 99, 100, 101, 102, 166,
	235, 250, 69, 231, 236, 178, 56, 57, 70, 31,
	23, 258, 58, 73, 20, 65, 66, 67, 263, 62,
	63, 61, 64, 14, 74, 84, 85, 87, 89, 86,
	88, 90, 91, 59, 60, 75, 76, 77, 33, 25,
	22, 105, 103, 104, 97, 98, 93, 95, 94, 96,
	106, 107, 99, 100, 101, 102, 92, 186, 73, 72,
	65, 66, 67, 200, 62, 63, 61, 64, 233, 74,
	69, 199, 105, 103, 104, 246, 70, 228, 59, 60,
	112, 106, 107, 99, 100, 101, 102, 166, 73, 223,
	65, 66, 67, 195, 62, 63, 61, 64, 204, 74,
	226, 44, 163, 132, 43, 131, 220, 219, 59, 60,
	162, 221, 222, 181, 141, 69, 180, 105, 103, 104,
	79, 70, 9, 11, 12, 112, 106, 107, 99, 100,
	101, 102, 166, 46, 47, 224, 78, 32, 27, 15,
	254, 1, 6, 10, 130, 69, 185, 105, 103, 104,
	184, 70, 45, 218, 183, 112, 106, 107, 99, 100,
	101, 102, 166, 105, 103, 104, 209, 34, 24, 29,
	203, 21, 106, 107, 99, 100, 101, 102, 166, 19,
	16, 2, 3, 0, 0, 0, 173, 105, 103, 104,
	0, 0, 0, 0, 0, 0, 106, 107, 99, 100,
	101, 102, 166, 105, 103, 104, 214, 0, 0, 0,
	0, 0, 106, 107, 99, 100, 101, 102, 166, 0,
	0, 0, 0, 211, 210, 215, 216, 217, 212, 213,
}
var xxPact = [...]int{

	-1000, 178, -1000, -1000, 189, -1000, 356, 182, -1000, 251,
	-1000, -1000, -1000, -1000, -1000, 42, 96, 242, 271, 238,
	-1000, 269, 41, -1000, -1000, 40, 237, 267, 215, 237,
	-1000, 36, 81, 39, 215, -1000, 7, -1000, 323, -1000,
	173, -1000, 161, -1000, -1000, 204, -1000, -1000, 73, -1000,
	-1000, -1000, 224, 131, 241, 118, 173, 173, 173, -1000,
	-1000, 5, -1000, -1000, -1000, 123, -35, -41, -36, 286,
	286, -1000, -1000, -1000, -1000, -1000, -1000, -1000, 176, 158,
	-1000, -1000, -1000, -1000, 147, 286, 286, 286, 286, 286,
	286, 286, 316, 286, 286, 286, 286, 286, 286, 286,
	286, 286, 286, 286, 286, 286, 286, 286, 286, -4,
	157, 386, 286, 33, -1000, -1000, -22, -32, 73, 286,
	-4, 286, 286, 233, 286, 173, -1000, -1000, -1000, -1000,
	290, 173, 173, -1000, 386, 386, 386, 386, 386, 386,
	386, 33, -1000, 386, 386, 386, 386, 386, 386, 67,
	67, -1000, -1000, 167, 148, 10, 83, 83, 386, -1000,
	286, -1000, 38, -17, 32, -1000, 286, 346, 121, -1000,
	219, -1000, -1000, -1000, 330, -1000, 255, 107, -1000, 74,
	-24, -60, -1000, 439, 322, -1000, -1000, -1000, 54, -1000,
	-1000, 370, 4, 45, 231, -1000, -1000, -1000, -4, 227,
	-61, -1000, 51, -1000, -1000, -1000, -1000, -1000, 173, -1000,
	-1000, -1000, -1000, -1000, -1000, -13, -14, -15, -1000, -1000,
	-1000, -1000, -1000, -1000, 286, 173, -1000, -36, -1000, 286,
	-1000, -1000, -1000, -62, -1000, -1000, -1000, -1000, 219, -1000,
	-1000, 203, 163, 159, 300, -6, -63, 370, -1000, 227,
	-1000, -18, -26, -27, -1000, -1000, -1000, 286, -1000, -1000,
	193, -1000, -1000, 386, -28, -1000,
}
var xxPgo = [...]int{

	0, 422, 421, 420, 419, 411, 409, 171, 408, 407,
	163, 406, 394, 393, 390, 386, 384, 383, 382, 381,
	379, 378, 377, 3, 376, 360, 6, 0, 356, 353,
	4, 42, 5, 147, 350, 7, 8, 345, 343, 342,
	340, 333, 317, 315, 311, 308, 1, 303, 2, 299,
}
var xxR1 = [...]int{

	0, 19, 19, 19, 19, 19, 1, 20, 21, 2,
	5, 5, 8, 8, 22, 18, 18, 17, 17, 3,
	3, 4, 4, 6, 6, 7, 7, 7, 7, 7,
	9, 9, 24, 10, 25, 10, 10, 12, 12, 11,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
	11, 14, 14, 13, 13, 13, 13, 13, 16, 16,
	15, 26, 26, 26, 26, 28, 28, 29, 29, 31,
	23, 30, 30, 30, 30, 30, 30, 30, 30, 30,
	30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
	30, 30, 30, 37, 30, 38, 30, 30, 30, 30,
	30, 30, 30, 30, 30, 34, 34, 39, 39, 40,
	40, 42, 42, 32, 43, 43, 41, 44, 35, 35,
	45, 45, 46, 46, 36, 47, 47, 48, 48, 33,
	33, 49, 49, 49, 27, 27, 27, 27, 27, 27,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
	27,
}
var xxR2 = [...]int{

	0, 0, 2, 2, 3, 2, 2, 0, 0, 11,
	0, 3, 0, 3, 3, 0, 2, 1, 1, 0,
	2, 1, 2, 1, 2, 3, 3, 4, 3, 3,
	1, 2, 0, 5, 0, 5, 4, 0, 2, 1,
	1, 1, 1, 1, 1, 4, 6, 1, 4, 1,
	4, 0, 2, 1, 1, 1, 1, 1, 0, 2,
	1, 1, 3, 4, 4, 0, 1, 1, 3, 1,
	1, 1, 1, 3, 3, 3, 3, 3, 3, 3,
	3, 1, 3, 3, 3, 7, 3, 3, 4, 4,
	5, 2, 2, 0, 4, 0, 4, 3, 3, 3,
	3, 3, 3, 1, 3, 3, 2, 1, 3, 1,
	1, 3, 1, 5, 1, 3, 1, 0, 4, 1,
	1, 3, 1, 1, 3, 1, 3, 1, 2, 1,
	1, 1, 1, 1, 3, 1, 1, 4, 1, 1,
	1, 3, 1, 4, 1, 4, 1, 1, 2, 3,
	3, 3, 3, 3, 3, 3, 3, 2, 3, 3,
	1,
}
var xxChk = [...]int{

	-1000, -19, -2, -1, 54, 4, -18, 49, 21, 6,
	-17, 7, 8, 21, 12, -20, -3, 77, 52, -4,
	12, -5, 9, 12, -8, 10, 77, -21, 77, -6,
	-7, 12, -22, 11, -9, -10, 13, -7, 78, 53,
	77, -10, 78, 21, 18, 69, 50, 51, -23, -30,
	50, 51, -27, 13, 39, -33, 73, 74, 79, 32,
	33, 20, 18, 19, 21, 14, 15, 16, -26, 69,
	75, -31, -49, 12, 23, 34, 35, 36, -24, -25,
	22, 18, 56, 55, 41, 42, 45, 43, 46, 44,
	47, 48, 72, 62, 64, 63, 65, 60, 61, 68,
	69, 70, 71, 58, 59, 57, 66, 67, 31, 37,
	-33, -27, 79, 38, -23, -23, -30, -27, -23, 79,
	37, 82, 82, 81, 82, 79, -27, -27, 21, 23,
	-16, -37, -38, -31, -27, -27, -27, -27, -27, -27,
	-27, 38, -27, -27, -27, -27, -27, -27, -27, -27,
	-27, -27, -27, -27, -27, -27, -27, -27, -27, -32,
	79, 2, -34, -39, 38, 12, 72, -27, -35, -36,
	79, 40, 80, 80, -27, -32, -27, -27, 12, -27,
	-28, -29, -30, -12, -14, -15, 7, -23, -23, -35,
	-36, -27, 77, 37, 84, -41, -35, 79, 37, -44,
	-47, -48, 12, 80, 83, 83, 83, 80, 84, -11,
	25, 24, 29, 30, 7, 26, 27, 28, -13, 25,
	24, 29, 30, 7, 5, 79, -40, -26, -42, 79,
	-32, 12, -32, -45, -46, 13, 17, 80, 84, 70,
	-30, 79, 79, 79, -27, -23, -43, -27, 80, 84,
	-48, 18, 21, 21, 80, 80, 80, 84, -46, 80,
	69, 80, 80, -27, 18, 80,
}
var xxDef = [...]int{

	1, -2, 2, 3, 0, 5, 0, 0, 4, 0,
	16, 17, 18, 6, 7, 19, 0, 0, 10, 20,
	21, 12, 0, 22, 8, 0, 0, 0, 0, 11,
	23, 0, 0, 0, 13, 30, 0, 24, 0, 9,
	0, 31, -2, 25, 26, 0, 28, 29, 14, 70,
	71, 72, -2, 81, 0, 0, 0, 0, 0, 135,
	136, 0, 138, 139, 140, 142, 144, 146, 147, 0,
	0, 160, 130, 61, 69, 131, 132, 133, 0, 0,
	58, 27, 93, 95, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 129, 0, 0, 91, 92, 70, -2, 0, 0,
	0, 0, 0, 0, 0, 65, 148, 157, 37, 51,
	36, 0, 0, 73, 74, 75, 76, 77, 78, 79,
	80, 0, 153, 97, 98, 99, 100, 101, 102, 149,
	150, 151, 152, 154, 155, 156, 158, 159, 82, 83,
	0, 84, 0, 0, 0, 107, 0, 0, 86, 87,
	117, 119, 104, 134, 0, 141, 0, 0, 62, 0,
	0, 66, -2, 33, 35, 59, 60, 94, 96, 88,
	89, 0, 0, 0, 0, 106, 116, 117, 0, 0,
	0, 125, 127, 137, 143, 145, 63, 64, 0, 38,
	39, 40, 41, 42, 43, 44, 47, 49, 52, 53,
	54, 55, 56, 57, 0, 0, 105, 109, 110, 0,
	112, 108, 90, 0, 120, 122, 123, 124, 0, 128,
	-2, 0, 0, 0, 0, 0, 0, 114, 118, 0,
	126, 0, 0, 0, 113, 85, 111, 0, 121, 45,
	0, 48, 50, 115, 0, 46,
}
var xxTok1 = [...]int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 72, 59, 3,
	79, 80, 70, 68, 84, 69, 81, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 77, 3,
	3, 78, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 82, 71, 83, 58, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 57, 3, 75,
}
var xxTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
	52, 53, 54, 55, 56, 60, 61, 62, 63, 64,
	65, 66, 67, 73, 74, 76,
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
//line /grammar/grammar.y:164
		{
			ParsedRuleset.Rules = append(ParsedRuleset.Rules, xxDollar[2].yr)
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:167
		{
			ParsedRuleset.Imports = append(ParsedRuleset.Imports, xxDollar[2].s)
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:170
		{
			ParsedRuleset.Includes = append(ParsedRuleset.Includes, xxDollar[3].s)
		}
	case 5:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:173
		{
		}
	case 6:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:179
		{
			xxVAL.s = xxDollar[2].s
		}
	case 7:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:187
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
//line /grammar/grammar.y:200
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
//line /grammar/grammar.y:237
		{
			c := conditionBuilder.String()
			c = strings.TrimLeft(c, ":\n\r\t ")
			c = strings.TrimRight(c, "}\n\r\t ")
			xxDollar[4].yr.Condition = c
			xxVAL.yr = xxDollar[4].yr
		}
	case 10:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:249
		{

		}
	case 11:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:253
		{
			xxVAL.m = make(data.Metas, 0, len(xxDollar[3].mps))
			for _, mpair := range xxDollar[3].mps {
				// YARA is ok with duplicate keys; we follow suit
				xxVAL.m = append(xxVAL.m, mpair)
			}
		}
	case 12:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:265
		{
			xxVAL.yss = data.Strings{}
		}
	case 13:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:269
		{
			xxVAL.yss = xxDollar[3].yss
		}
	case 15:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:281
		{
			xxVAL.rm = data.RuleModifiers{}
		}
	case 16:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:282
		{
			xxVAL.rm.Private = xxVAL.rm.Private || xxDollar[2].rm.Private
			xxVAL.rm.Global = xxVAL.rm.Global || xxDollar[2].rm.Global
		}
	case 17:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:290
		{
			xxVAL.rm.Private = true
		}
	case 18:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:291
		{
			xxVAL.rm.Global = true
		}
	case 19:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:297
		{
			xxVAL.ss = []string{}
		}
	case 20:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:301
		{
			xxVAL.ss = xxDollar[2].ss
		}
	case 21:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:309
		{
			xxVAL.ss = []string{xxDollar[1].s}
		}
	case 22:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:313
		{
			xxVAL.ss = append(xxDollar[1].ss, xxDollar[2].s)
		}
	case 23:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:321
		{
			xxVAL.mps = data.Metas{xxDollar[1].mp}
		}
	case 24:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:322
		{
			xxVAL.mps = append(xxVAL.mps, xxDollar[2].mp)
		}
	case 25:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:328
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].s}
		}
	case 26:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:332
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, xxDollar[3].i64}
		}
	case 27:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:336
		{
			switch xxDollar[4].i64.(type) {
			case data.Dec:
				xxDollar[4].i64 = data.Dec(-xxDollar[4].i64.Value())
			case data.Oct:
				xxDollar[4].i64 = data.Oct(-xxDollar[4].i64.Value())
			case data.Hex:
				xxDollar[4].i64 = data.Hex(-xxDollar[4].i64.Value())
			default:
				panic(fmt.Errorf(`unknown integer format type %T`, xxDollar[4].i64))
			}
			xxVAL.mp = data.Meta{xxDollar[1].s, -xxDollar[4].i64.Value()}
		}
	case 28:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:350
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, true}
		}
	case 29:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:354
		{
			xxVAL.mp = data.Meta{xxDollar[1].s, false}
		}
	case 30:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:361
		{
			xxVAL.yss = data.Strings{xxDollar[1].ys}
		}
	case 31:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:362
		{
			xxVAL.yss = append(xxDollar[1].yss, xxDollar[2].ys)
		}
	case 32:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:368
		{
			xxVAL.ys.Type = data.TypeString
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 33:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:373
		{
			xxDollar[3].ys.Text = xxDollar[4].s
			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 34:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:380
		{
			xxVAL.ys.Type = data.TypeRegex
			xxVAL.ys.ID = xxDollar[1].s
		}
	case 35:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:385
		{
			xxDollar[3].ys.Text = xxDollar[4].reg.text

			xxDollar[5].mod.I = xxDollar[4].reg.mods.I
			xxDollar[5].mod.S = xxDollar[4].reg.mods.S

			xxDollar[3].ys.Modifiers = xxDollar[5].mod

			xxVAL.ys = xxDollar[3].ys
		}
	case 36:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:396
		{
			xxVAL.ys.Type = data.TypeHexString
			xxVAL.ys.ID = xxDollar[1].s
			xxVAL.ys.Text = xxDollar[3].s
			xxVAL.ys.Modifiers = xxDollar[4].mod
		}
	case 37:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:406
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 38:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:409
		{
			xor := xxDollar[1].mod.Xor
			if xor == nil {
				xor = xxDollar[2].mod.Xor
			} else if xxDollar[2].mod.Xor != nil {
				panic(data.NewYARAError(
					data.ErrInvalidStringModifierCombo,
					`repeated "xor" modifier`))
			}

			b64 := xxDollar[1].mod.Base64
			if b64 == nil {
				b64 = xxDollar[2].mod.Base64
			} else if xxDollar[2].mod.Base64 != nil {
				panic(data.NewYARAError(
					data.ErrInvalidStringModifierCombo,
					`repeated "base64" modifier`))
			}

			b64w := xxDollar[1].mod.Base64Wide
			if b64w == nil {
				b64w = xxDollar[2].mod.Base64Wide
			} else if xxDollar[2].mod.Base64Wide != nil {
				panic(data.NewYARAError(
					data.ErrInvalidStringModifierCombo,
					`repeated "base64wide" modifier`))
			}

			xxVAL.mod = data.StringModifiers{
				Wide:       xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:      xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:     xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword:   xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
				Private:    xxDollar[1].mod.Private || xxDollar[2].mod.Private,
				Xor:        xor,
				Base64:     b64,
				Base64Wide: b64w,
			}

			if xxVAL.mod.Xor != nil && xxVAL.mod.Nocase {
				panic(data.NewYARAError(
					data.ErrInvalidStringModifierCombo,
					`xor nocase`))
			}
		}
	case 39:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:458
		{
			xxVAL.mod.Wide = true
		}
	case 40:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:459
		{
			xxVAL.mod.ASCII = true
		}
	case 41:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:460
		{
			xxVAL.mod.Nocase = true
		}
	case 42:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:461
		{
			xxVAL.mod.Fullword = true
		}
	case 43:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:462
		{
			xxVAL.mod.Private = true
		}
	case 44:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:464
		{
			xxVAL.mod.Xor = data.Xor{}
		}
	case 45:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:468
		{
			if xxDollar[3].i64.Value() < 0 || xxDollar[3].i64.Value() > 255 {
				msg := fmt.Sprintf(`xor value %s outside of [0,255]`, xxDollar[3].i64)
				panic(data.NewYARAError(data.ErrInvalidStringModifierCombo, msg))
			}

			xxVAL.mod.Xor = data.Xor{xxDollar[3].i64}
		}
	case 46:
		xxDollar = xxS[xxpt-6 : xxpt+1]
//line /grammar/grammar.y:477
		{
			if xxDollar[3].i64.Value() < 0 || xxDollar[5].i64.Value() > 255 || xxDollar[3].i64.Value() > xxDollar[5].i64.Value() {
				msg := fmt.Sprintf(`xor value %s or %s outside of [0,255]`, xxDollar[3].i64, xxDollar[5].i64)
				panic(data.NewYARAError(data.ErrInvalidStringModifierCombo, msg))
			}

			xxVAL.mod.Xor = data.Xor{xxDollar[3].i64, xxDollar[5].i64}
		}
	case 47:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:486
		{
			xxVAL.mod.Base64 = data.Base64{}
		}
	case 48:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:490
		{
			if len(xxDollar[3].s) != 64 {
				err := fmt.Errorf(`base64 value must be 64 characters; got %d`, len(xxDollar[3].s))
				panic(err)
			}
			xxVAL.mod.Base64 = data.Base64(xxDollar[3].s)
		}
	case 49:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:498
		{
			xxVAL.mod.Base64Wide = data.Base64{}
		}
	case 50:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:502
		{
			if len(xxDollar[3].s) != 64 {
				err := fmt.Errorf(`base64wide value must be 64 characters; got %d`, len(xxDollar[3].s))
				panic(err)
			}
			xxVAL.mod.Base64Wide = data.Base64(xxDollar[3].s)
		}
	case 51:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:514
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 52:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:517
		{
			xxVAL.mod = data.StringModifiers{
				Wide:     xxDollar[1].mod.Wide || xxDollar[2].mod.Wide,
				ASCII:    xxDollar[1].mod.ASCII || xxDollar[2].mod.ASCII,
				Nocase:   xxDollar[1].mod.Nocase || xxDollar[2].mod.Nocase,
				Fullword: xxDollar[1].mod.Fullword || xxDollar[2].mod.Fullword,
				Private:  xxDollar[1].mod.Private || xxDollar[2].mod.Private,
			}
		}
	case 53:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:530
		{
			xxVAL.mod.Wide = true
		}
	case 54:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:531
		{
			xxVAL.mod.ASCII = true
		}
	case 55:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:532
		{
			xxVAL.mod.Nocase = true
		}
	case 56:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:533
		{
			xxVAL.mod.Fullword = true
		}
	case 57:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:534
		{
			xxVAL.mod.Private = true
		}
	case 58:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:540
		{
			xxVAL.mod = data.StringModifiers{}
		}
	case 59:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:544
		{
			xxVAL.mod = data.StringModifiers{
				Private: xxDollar[1].mod.Private || xxDollar[2].mod.Private,
			}
		}
	case 60:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:553
		{
			xxVAL.mod.Private = true
		}
	case 61:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:559
		{

		}
	case 62:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:563
		{

		}
	case 63:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:567
		{

		}
	case 64:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:572
		{

		}
	case 65:
		xxDollar = xxS[xxpt-0 : xxpt+1]
//line /grammar/grammar.y:579
		{
		}
	case 66:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:580
		{
		}
	case 67:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:585
		{

		}
	case 68:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:589
		{

		}
	case 69:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:597
		{

		}
	case 70:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:605
		{

		}
	case 71:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:612
		{

		}
	case 72:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:616
		{

		}
	case 73:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:620
		{

		}
	case 74:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:624
		{

		}
	case 75:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:628
		{

		}
	case 76:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:632
		{

		}
	case 77:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:636
		{

		}
	case 78:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:640
		{

		}
	case 79:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:644
		{

		}
	case 80:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:648
		{

		}
	case 81:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:652
		{

		}
	case 82:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:656
		{

		}
	case 83:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:660
		{

		}
	case 84:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:664
		{

		}
	case 85:
		xxDollar = xxS[xxpt-7 : xxpt+1]
//line /grammar/grammar.y:668
		{

		}
	case 86:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:672
		{

		}
	case 87:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:676
		{

		}
	case 88:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:680
		{

		}
	case 89:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:684
		{

		}
	case 90:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:688
		{

		}
	case 91:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:692
		{

		}
	case 92:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:696
		{

		}
	case 93:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:700
		{

		}
	case 94:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:704
		{

		}
	case 95:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:708
		{

		}
	case 96:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:712
		{

		}
	case 97:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:716
		{

		}
	case 98:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:720
		{

		}
	case 99:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:724
		{

		}
	case 100:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:728
		{

		}
	case 101:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:732
		{

		}
	case 102:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:736
		{

		}
	case 103:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:740
		{

		}
	case 104:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:744
		{

		}
	case 105:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:752
		{

		}
	case 106:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:756
		{

		}
	case 107:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:764
		{

		}
	case 108:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:768
		{

		}
	case 109:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:776
		{

		}
	case 110:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:780
		{

		}
	case 111:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:787
		{
		}
	case 112:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:788
		{
		}
	case 113:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line /grammar/grammar.y:794
		{

		}
	case 114:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:802
		{

		}
	case 115:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:806
		{

		}
	case 116:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:814
		{

		}
	case 117:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:822
		{

		}
	case 119:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:827
		{

		}
	case 122:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:841
		{

		}
	case 123:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:845
		{

		}
	case 124:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:853
		{

		}
	case 125:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:861
		{

		}
	case 126:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:865
		{

		}
	case 127:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:873
		{

		}
	case 128:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:877
		{

		}
	case 130:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:886
		{

		}
	case 131:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:894
		{

		}
	case 132:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:898
		{

		}
	case 133:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:902
		{

		}
	case 134:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:910
		{

		}
	case 135:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:914
		{

		}
	case 136:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:918
		{

		}
	case 137:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:922
		{

		}
	case 138:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:926
		{

		}
	case 139:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:930
		{

		}
	case 140:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:934
		{

		}
	case 141:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:938
		{

		}
	case 142:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:942
		{

		}
	case 143:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:946
		{

		}
	case 144:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:950
		{

		}
	case 145:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line /grammar/grammar.y:954
		{

		}
	case 146:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:958
		{

		}
	case 147:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:962
		{

		}
	case 148:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:966
		{

		}
	case 149:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:970
		{

		}
	case 150:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:974
		{

		}
	case 151:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:978
		{

		}
	case 152:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:982
		{

		}
	case 153:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:986
		{

		}
	case 154:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:990
		{

		}
	case 155:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:994
		{

		}
	case 156:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:998
		{

		}
	case 157:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line /grammar/grammar.y:1002
		{

		}
	case 158:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:1006
		{

		}
	case 159:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line /grammar/grammar.y:1010
		{

		}
	case 160:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line /grammar/grammar.y:1014
		{

		}
	}
	goto xxstack /* stack new state and value */
}
