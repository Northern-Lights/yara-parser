%{
package grammar

import (
    "fmt"
    "strings"

    "github.com/Northern-Lights/yara-parser/data"
)

var (
    ParsedRuleset data.RuleSet
)

type metaPair struct {
    key string
    val interface{}
}

type regexPair struct {
    text string
    mods data.StringModifiers
}

%}

%token _DOT_DOT_
%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
%token _STRINGS_
%token _CONDITION_
%token <s> _IDENTIFIER_
%token <s> _STRING_IDENTIFIER_
%token _STRING_COUNT_
%token _STRING_OFFSET_
%token _STRING_LENGTH_
%token _STRING_IDENTIFIER_WITH_WILDCARD_
%token <i64> _NUMBER_
%token _DOUBLE_
%token _INTEGER_FUNCTION_
%token <s> _TEXT_STRING_
%token <s> _HEX_STRING_
%token <reg> _REGEXP_
%token <mod> _ASCII_
%token <mod> _WIDE_
%token <mod> _NOCASE_
%token <mod> _FULLWORD_
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

%type <s>   import
%type <yr>  rule
%type <ss>  tags
%type <ss>  tag_list
%type <m>   meta
%type <mps> meta_declarations
%type <mp>  meta_declaration
%type <yss> strings
%type <yss> string_declarations
%type <ys>  string_declaration
%type <mod> string_modifier
%type <mod> string_modifiers
%type <rm>  rule_modifier
%type <rm>  rule_modifiers

%union {
    i64           int64
    s             string
    ss            []string

    rm            data.RuleModifiers
    m             map[string]interface{}
    mp            metaPair
    mps           []metaPair
    mod           data.StringModifiers
    reg           regexPair
    ys            data.String
    yss           []data.String
    yr            data.Rule
}


%%

rules
    : /* empty */
    | rules rule {
        ParsedRuleset.Rules = append(ParsedRuleset.Rules, $2)
    }
    | rules import {
        ParsedRuleset.Imports = append(ParsedRuleset.Imports, $2)
    }
    | rules _INCLUDE_ _TEXT_STRING_ {
        ParsedRuleset.Includes = append(ParsedRuleset.Includes, $3)
    }
    | rules error rule {
        ParsedRuleset.Rules = append(ParsedRuleset.Rules, $3)
    }
    | rules error import {
        ParsedRuleset.Imports = append(ParsedRuleset.Imports, $3)
    }
    | rules error _INCLUDE_ _TEXT_STRING_ {
        ParsedRuleset.Includes = append(ParsedRuleset.Includes, $4)
    }
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
          $$ = $2
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_
      {
          $$.Modifiers = $1
          $$.Identifier = $3
      }
      tags _LBRACE_ meta strings
      {
          // $4 is the rule created in above action
          // Can we access using $<rule>4?
          $<yr>4.Tags = $5
          $<yr>4.Meta = $7
          $<yr>4.Strings = make(map[string]*data.String)
          for _, s := range $8 {
              if _, had := $<yr>4.Strings[s.ID]; had {
                  err := fmt.Errorf(`duplicated string identifier "%s"`, s.ID)
                  panic(err)
              }
              s := s
              $<yr>4.Strings[s.ID] = &s
          }
      }
      condition _RBRACE_
      {
          c := conditionBuilder.String()
          c = strings.TrimLeft(c, ":\n\r\t ")
          c = strings.TrimRight(c, "}\n\r\t ")
          $<yr>4.Condition = c
          $$ = $<yr>4
      }
    ;


meta
    : /* empty */
      {
        
      }
    | _META_ _COLON_ meta_declarations
      {
          $$ = make(map[string]interface{})
          for _, mpair := range $3 {
              // YARA is ok with duplicate keys; we follow suit
              $$[mpair.key] = mpair.val
          }
      }
    ;


strings
    : /* empty */
      {
          $$ = []data.String{}
      }
    | _STRINGS_ _COLON_ string_declarations
      {
          $$ = $3
      }
    ;


condition
    : _CONDITION_ _COLON_ boolean_expression
    ;


rule_modifiers
    : /* empty */ { $$ = data.RuleModifiers{} }
    | rule_modifiers rule_modifier     {
        $$.Private = $$.Private || $2.Private
        $$.Global = $$.Global || $2.Global
    }
    ;


rule_modifier
    : _PRIVATE_      { $$.Private = true }
    | _GLOBAL_       { $$.Global = true }
    ;


tags
    : /* empty */
      {
          $$ = []string{}
      }
    | _COLON_ tag_list
      {
          $$ = $2
      }
    ;


tag_list
    : _IDENTIFIER_
      {
          $$ = []string{$1}
      }
    | tag_list _IDENTIFIER_
      {
          $$ = append($1, $2)
      }
    ;



meta_declarations
    : meta_declaration                    { $$ = []metaPair{$1} }
    | meta_declarations meta_declaration  { $$ = append($$, $2)}
    ;


meta_declaration
    : _IDENTIFIER_ _EQUAL_SIGN_ _TEXT_STRING_
      {
          $$ = metaPair{$1, $3}
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _NUMBER_
      {
          $$ = metaPair{$1, $3}
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _MINUS_ _NUMBER_
      {
          $$ = metaPair{$1, -$4}
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _TRUE_
      {
          $$ = metaPair{$1, true}
      }
    | _IDENTIFIER_ _EQUAL_SIGN_ _FALSE_
      {
          $$ = metaPair{$1, false}
      }
    ;


string_declarations
    : string_declaration                      { $$ = []data.String{$1} }
    | string_declarations string_declaration  { $$ = append($1, $2) }
    ;


string_declaration
    : _STRING_IDENTIFIER_ _EQUAL_SIGN_
      {
          $$.Type = data.TypeString
          $$.ID = $1
      }
      _TEXT_STRING_ string_modifiers
      {
          $<ys>3.Text = $4
          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ _EQUAL_SIGN_
      {
          $$.Type = data.TypeRegex
          $$.ID = $1
      }
      _REGEXP_ string_modifiers
      {
          $<ys>3.Text = $4.text

          $5.I = $4.mods.I
          $5.S = $4.mods.S

          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ _EQUAL_SIGN_ _HEX_STRING_
      {
          $$.Type = data.TypeHexString
          $$.ID = $1
          $$.Text = $3
      }
    ;


string_modifiers
    : /* empty */                         { }
    | string_modifiers string_modifier    {
          $$ = data.StringModifiers {
              Wide: $1.Wide || $2.Wide,
              ASCII: $1.ASCII || $2.ASCII,
              Nocase: $1.Nocase || $2.Nocase,
              Fullword: $1.Fullword || $2.Fullword,
          }
    }
    ;


string_modifier
    : _WIDE_        { $$.Wide = true }
    | _ASCII_       { $$.ASCII = true }
    | _NOCASE_      { $$.Nocase = true }
    | _FULLWORD_    { $$.Fullword = true }
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
