%{
package grammar

import (
    "yara-parser/data"
)

var ParsedRuleset data.RuleSet
%}

%token _DOT_DOT_
%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
%token <string> _STRINGS_
%token _CONDITION_
%token <c_string> _IDENTIFIER_
%token <c_string> _STRING_IDENTIFIER_
%token <c_string> _STRING_COUNT_
%token <c_string> _STRING_OFFSET_
%token <c_string> _STRING_LENGTH_
%token <c_string> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <integer> _NUMBER_
%token <double_> _DOUBLE_
%token <integer> _INTEGER_FUNCTION_
%token <sized_string> _TEXT_STRING_
%token <sized_string> _HEX_STRING_
%token <sized_string> _REGEXP_
%token _ASCII_
%token _WIDE_
%token _NOCASE_
%token _FULLWORD_
%token _AT_
%token _FILESIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token _MATCHES_
%token _CONTAINS_
%token _IMPORT_

%token _TRUE_
%token _FALSE_

%token _LPAREN_ _RPAREN_
%token _LBRACE_ _RBRACE_
%token _LBRACKET_ _RBRACKET_
%token _COLON_
%token _DOT_
%token _EQUAL_SIGN_
%token _COMMA_
%token _INCLUDE_

%left _OR_
%left _AND_
%left _PIPE_
%left _CARAT_
%left _AMP_
%left _EQ_ _NEQ_
%left _LT_ _LE_ _GT_ _GE_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left _PLUS_ _MINUS_
%left _ASTERISK_ _BACKSLASH_ _PERCENT_
%right _NOT_ _TILDE_ UNARY_MINUS

%type <rule>   rule

%type <string> strings
%type <string> string_declaration
%type <string> string_declarations

%type <meta> meta
%type <meta> meta_declaration
%type <meta> meta_declarations

%type <c_string> tags
%type <c_string> tag_list

%type <integer> string_modifier
%type <integer> string_modifiers

%type <integer> integer_set

%type <integer> rule_modifier
%type <integer> rule_modifiers

%type <expression> primary_expression
%type <expression> boolean_expression
%type <expression> expression
%type <expression> identifier
%type <expression> regexp

%type <c_string> arguments
%type <c_string> arguments_list

%union {
  expression string
  sized_string string
  c_string string
  integer string
  double_ string
  string string
  meta string
  rule string
}


%%

rules
    : /* empty */
    | rules rule
    | rules import
    | rules error rule      /* on error skip until next rule..*/
    | rules error import    /* .. or import statement */
    | rules error _INCLUDE_ /* .. or include statement */
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
        
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_
      {
        
      }
      tags _LBRACE_ meta strings
      {
       
      }
      condition _RBRACE_
      {
        
      }
    ;


meta
    : /* empty */
      {
        
      }
    | _META_ _COLON_ meta_declarations
      {
        
      }
    ;


strings
    : /* empty */
      {
        
      }
    | _STRINGS_ _COLON_ string_declarations
      {
        
      }
    ;


condition
    : _CONDITION_ _COLON_ boolean_expression
    ;


rule_modifiers
    : /* empty */                      { }
    | rule_modifiers rule_modifier     { }
    ;


rule_modifier
    : _PRIVATE_      { }
    | _GLOBAL_       { }
    ;


tags
    : /* empty */
      {
        
      }
    | _COLON_ tag_list
      {
        
      }
    ;


tag_list
    : _IDENTIFIER_
      {
        
      }
    | tag_list _IDENTIFIER_
      {
        
      }
    ;



meta_declarations
    : meta_declaration                    { }
    | meta_declarations meta_declaration  { }
    ;


meta_declaration
    : _IDENTIFIER_ _EQUAL_SIGN_ _TEXT_STRING_
      {
        
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _NUMBER_
      {
        
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _MINUS_ _NUMBER_
      {
        
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _TRUE_
      {
        
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _FALSE_
      {
        
      }
    ;


string_declarations
    : string_declaration                      { }
    | string_declarations string_declaration  { }
    ;


string_declaration
    : _STRING_IDENTIFIER_ _EQUAL_SIGN_
      {
        
      }
      _TEXT_STRING_ string_modifiers
      {
        
      }
    | _STRING_IDENTIFIER_ _EQUAL_SIGN_
      {
        
      }
      _REGEXP_ string_modifiers
      {
        
      }
    | _STRING_IDENTIFIER_ _EQUAL_SIGN_ _HEX_STRING_
      {
        
      }
    ;


string_modifiers
    : /* empty */                         { }
    | string_modifiers string_modifier    { }
    ;


string_modifier
    : _WIDE_        { }
    | _ASCII_       { }
    | _NOCASE_      { }
    | _FULLWORD_    { }
    ;


identifier
    : _IDENTIFIER_
      {
        
      }
    | identifier _DOT_ _IDENTIFIER_
      {
        
      }
    | identifier _LBRACKET_ primary_expression _RBRACKET_
      {
        
      }

    | identifier _LPAREN_ arguments _RPAREN_
      {
        
      }
    ;


arguments
    : /* empty */     { }
    | arguments_list  { }


arguments_list
    : expression
      {
        
      }
    | arguments_list _COMMA_ expression
      {
        
      }
    ;


regexp
    : _REGEXP_
      {
        
      }
    ;


boolean_expression
    : expression
      {
        
      }
    ;

expression
    : _TRUE_
      {
        
      }
    | _FALSE_
      {
        
      }
    | primary_expression _MATCHES_ regexp
      {
        
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        
      }
    | _STRING_IDENTIFIER_
      {
        
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        
      }
    | _FOR_ for_expression error
      {
        
      }
    | _FOR_ for_expression _IDENTIFIER_ _IN_
      {
        
      }
      _LPAREN_ boolean_expression _RPAREN_
      {
        
      }
    | _FOR_ for_expression _OF_ string_set _COLON_
      {
        
      }
      _LPAREN_ boolean_expression _RPAREN_
      {
        
      }
    | for_expression _OF_ string_set
      {
        
      }
    | _NOT_ boolean_expression
      {
        
      }
    | boolean_expression _AND_
      {
        
      }
      boolean_expression
      {
        
      }
    | boolean_expression _OR_
      {
        
      }
      boolean_expression
      {
        
      }
    | primary_expression _LT_ primary_expression
      {
        
      }
    | primary_expression _GT_ primary_expression
      {
        
      }
    | primary_expression _LE_ primary_expression
      {
        
      }
    | primary_expression _GE_ primary_expression
      {
        
      }
    | primary_expression _EQ_ primary_expression
      {
        
      }
    | primary_expression _NEQ_ primary_expression
      {
        
      }
    | primary_expression
      {
        
      }
    |_LPAREN_ expression _RPAREN_
      {
        
      }
    ;


integer_set
    : _LPAREN_ integer_enumeration _RPAREN_  { }
    | range                        { }
    ;


range
    : _LPAREN_ primary_expression _DOT_DOT_  primary_expression _RPAREN_
      {
        
      }
    ;


integer_enumeration
    : primary_expression
      {
        
      }
    | integer_enumeration _COMMA_ primary_expression
      {
        
      }
    ;


string_set
    : _LPAREN_
      {
        
      }
      string_enumeration _RPAREN_
    | _THEM_
      {
        
      }
    ;


string_enumeration
    : string_enumeration_item
    | string_enumeration _COMMA_ string_enumeration_item
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {

      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        
      }
    ;


for_expression
    : primary_expression
    | _ALL_
      {
        
      }
    | _ANY_
      {
        
      }
    ;


primary_expression
    : _LPAREN_ primary_expression _RPAREN_
      {
        
      }
    | _FILESIZE_
      {
        
      }
    | _ENTRYPOINT_
      {
        
      }
    | _INTEGER_FUNCTION_ _LPAREN_ primary_expression _RPAREN_
      {
        
      }
    | _NUMBER_
      {
        
      }
    | _DOUBLE_
      {
        
      }
    | _TEXT_STRING_
      {
        
      }
    | _STRING_COUNT_
      {
        
      }
    | _STRING_OFFSET_ _LBRACKET_ primary_expression _RBRACKET_
      {
        
      }
    | _STRING_OFFSET_
      {
        
      }
    | _STRING_LENGTH_ _LBRACKET_ primary_expression _RBRACKET_
      {
        
      }
    | _STRING_LENGTH_
      {
        
      }
    | identifier
      {
        
      }
    | _MINUS_ primary_expression %prec UNARY_MINUS
      {
        
      }
    | primary_expression _PLUS_ primary_expression
      {
        
      }
    | primary_expression _MINUS_ primary_expression
      {
        
      }
    | primary_expression _ASTERISK_ primary_expression
      {
        
      }
    | primary_expression _BACKSLASH_ primary_expression
      {
        
      }
    | primary_expression _PERCENT_ primary_expression
      {
        
      }
    | primary_expression _CARAT_ primary_expression
      {
        
      }
    | primary_expression _AMP_ primary_expression
      {
        
      }
    | primary_expression _PIPE_ primary_expression
      {
        
      }
    | _TILDE_ primary_expression
      {
        
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
        
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
        
      }
    | regexp
      {
        
      }
    ;

%%
