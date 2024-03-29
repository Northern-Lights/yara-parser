/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

%{
package grammar

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

%}

// yara-parser: we have 'const eof = 0' in lexer.l
// Token that marks the end of the original file.
// %token _END_OF_FILE_  0

// TODO: yara-parser: https://github.com/VirusTotal/yara/blob/v3.8.1/libyara/lexer.l#L285
// Token that marks the end of included files, we can't use  _END_OF_FILE_
// because bison stops parsing when it sees _END_OF_FILE_, we want to be
// be able to identify the point where an included file ends, but continuing
// parsing any content that follows.
%token _END_OF_INCLUDED_FILE_

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
%token _XOR_
%token _BASE64_
%token _BASE64_WIDE_
%token <mod> _NOCASE_
%token <mod> _FULLWORD_
%token _AT_
%token _FILESIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _NONE_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token _MATCHES_
%token _CONTAINS_
%token _STARTSWITH_
%token _ENDSWITH_
%token _ICONTAINS_
%token _ISTARTSWITH_
%token _IENDSWITH_
%token _IEQUALS_
%token _IMPORT_

%token _TRUE_
%token _FALSE_

%token _LBRACE_ _RBRACE_
%token _INCLUDE_

%left _OR_
%left _AND_
%left '|'
%left '^'
%left '&'
%left _EQ_ _NEQ_
%left _LT_ _LE_ _GT_ _GE_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right _NOT_ _DEFINED_ '~' UNARY_MINUS

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
%type <mod> regexp_modifier
%type <mod> regexp_modifiers
%type <mod> hex_modifier
%type <mod> hex_modifiers
%type <rm>  rule_modifier
%type <rm>  rule_modifiers

%union {
    i64           data.Int
    s             string
    ss            []string

    rm            data.RuleModifiers
    m             data.Metas
    mp            data.Meta
    mps           data.Metas
    mod           data.StringModifiers
    reg           regexPair
    ys            data.String
    yss           data.Strings
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
    | rules _END_OF_INCLUDED_FILE_ { }
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

          // Forbid duplicate rules
          for _, r := range ParsedRuleset.Rules {
              if $3 == r.Identifier {
                  err := fmt.Errorf(`Duplicate rule "%s"`, $3)
                  panic(err)
              }
          }
      }
      tags _LBRACE_ meta strings
      {
          // $4 is the rule created in above action
          $<yr>4.Tags = $5

          // Forbid duplicate tags
          idx := make(map[string]struct{})
          for _, t := range $5 {
              if _, had := idx[t]; had {
                  msg := fmt.Sprintf(`grammar: Rule "%s" has duplicate tag "%s"`,
                      $<yr>4.Identifier,
                      t)
                  panic(msg)
              }
              idx[t] = struct{}{}
          }

          $<yr>4.Meta = $7

          $<yr>4.Strings = $8

          // Forbid duplicate string IDs, except `$` (anonymous)
          idx = make(map[string]struct{})
          for _, s := range $8 {
              if s.ID == "$" {
                  continue
              }
              if _, had := idx[s.ID]; had {
                  msg := fmt.Sprintf(
                    `grammar: Rule "%s" has duplicated string "%s"`,
                    $<yr>4.Identifier,
                    s.ID)
                  panic(msg)
              }
              idx[s.ID] = struct{}{}
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
    | _META_ ':' meta_declarations
      {
          $$ = make(data.Metas, 0, len($3))
          for _, mpair := range $3 {
              // YARA is ok with duplicate keys; we follow suit
              $$ = append($$, mpair)
          }
      }
    ;


strings
    : /* empty */
      {
          $$ = data.Strings{}
      }
    | _STRINGS_ ':' string_declarations
      {
          $$ = $3
      }
    ;


condition
    : _CONDITION_ ':' boolean_expression
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
    | ':' tag_list
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
    : meta_declaration                    { $$ = data.Metas{$1} }
    | meta_declarations meta_declaration  { $$ = append($$, $2)}
    ;


meta_declaration
    : _IDENTIFIER_ '=' _TEXT_STRING_
      {
          $$ = data.Meta{$1, $3}
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
          $$ = data.Meta{$1, $3}
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
          switch $4.(type) {
          case data.Dec:
              $4 = data.Dec(-$4.Value())
          case data.Oct:
              $4 = data.Oct(-$4.Value())
          case data.Hex:
              $4 = data.Hex(-$4.Value())
          default:
              panic(fmt.Errorf(`unknown integer format type %T`, $4))
          }
          $$ = data.Meta{$1, -$4.Value()}
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
          $$ = data.Meta{$1, true}
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
          $$ = data.Meta{$1, false}
      }
    ;


string_declarations
    : string_declaration                      { $$ = data.Strings{$1} }
    | string_declarations string_declaration  { $$ = append($1, $2) }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
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
    | _STRING_IDENTIFIER_ '='
      {
          $$.Type = data.TypeRegex
          $$.ID = $1
      }
      _REGEXP_ regexp_modifiers
      {
          $<ys>3.Text = $4.text

          $5.I = $4.mods.I
          $5.S = $4.mods.S

          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_ hex_modifiers
      {
          $$.Type = data.TypeHexString
          $$.ID = $1
          $$.Text = $3
          $$.Modifiers = $4
      }
    ;


string_modifiers
    : /* empty */                         {
      $$ = data.StringModifiers{}
    }
    | string_modifiers string_modifier    {
          xor := $1.Xor
          if xor == nil {
              xor = $2.Xor
          } else if $2.Xor != nil {
              panic(data.NewYARAError(
                  data.ErrInvalidStringModifierCombo,
                  `repeated "xor" modifier`))
          }

          b64 := $1.Base64
          if b64 == nil {
              b64 = $2.Base64
          } else if $2.Base64 != nil {
              panic(data.NewYARAError(
                data.ErrInvalidStringModifierCombo,
                `repeated "base64" modifier`))
          }

          b64w := $1.Base64Wide
          if b64w == nil {
              b64w = $2.Base64Wide
          } else if $2.Base64Wide != nil {
              panic(data.NewYARAError(
                data.ErrInvalidStringModifierCombo,
                `repeated "base64wide" modifier`))
          }

          $$ = data.StringModifiers {
              Wide: $1.Wide || $2.Wide,
              ASCII: $1.ASCII || $2.ASCII,
              Nocase: $1.Nocase || $2.Nocase,
              Fullword: $1.Fullword || $2.Fullword,
              Private: $1.Private || $2.Private,
              Xor: xor,
              Base64: b64,
              Base64Wide: b64w,
          }

          if $$.Xor != nil && $$.Nocase {
              panic(data.NewYARAError(
                  data.ErrInvalidStringModifierCombo,
                  `xor nocase`))
          }
    }
    ;


string_modifier
    : _WIDE_        { $$.Wide = true }
    | _ASCII_       { $$.ASCII = true }
    | _NOCASE_      { $$.Nocase = true }
    | _FULLWORD_    { $$.Fullword = true }
    | _PRIVATE_     { $$.Private = true }
    | _XOR_         
      {
          $$.Xor = data.Xor{}
      }
    | _XOR_ '(' _NUMBER_ ')'
      {
        if $3.Value() < 0 || $3.Value() > 255 {
          msg := fmt.Sprintf(`xor value %s outside of [0,255]`, $3)
          panic(data.NewYARAError(data.ErrInvalidStringModifierCombo, msg))
        }

        $$.Xor = data.Xor{$3}
      }
    | _XOR_ '(' _NUMBER_ '-' _NUMBER_ ')'
      {
        if $3.Value() < 0 || $5.Value() > 255 || $3.Value() > $5.Value() {
          msg := fmt.Sprintf(`xor value %s or %s outside of [0,255]`, $3, $5)
          panic(data.NewYARAError(data.ErrInvalidStringModifierCombo, msg))
        }
  
        $$.Xor = data.Xor{$3, $5}
      }
    | _BASE64_
      {
          $$.Base64 = data.Base64{}
      }
    | _BASE64_ '(' _TEXT_STRING_ ')'
      {
          if len($3) != 64 {
              err := fmt.Errorf(`base64 value must be 64 characters; got %d`, len($3))
              panic(err)
          }
          $$.Base64 = data.Base64($3)
      }
    | _BASE64_WIDE_
      {
          $$.Base64Wide = data.Base64{}
      }
    | _BASE64_WIDE_ '(' _TEXT_STRING_ ')'
      {
          if len($3) != 64 {
              err := fmt.Errorf(`base64wide value must be 64 characters; got %d`, len($3))
              panic(err)
          }
          $$.Base64Wide = data.Base64($3)
      }
    ;


regexp_modifiers
    : /* empty */
    {
      $$ = data.StringModifiers{}
    }
    | regexp_modifiers regexp_modifier    {
          $$ = data.StringModifiers {
              Wide: $1.Wide || $2.Wide,
              ASCII: $1.ASCII || $2.ASCII,
              Nocase: $1.Nocase || $2.Nocase,
              Fullword: $1.Fullword || $2.Fullword,
              Private: $1.Private || $2.Private,
          }
    }
    ;


regexp_modifier
    : _WIDE_        { $$.Wide = true }
    | _ASCII_       { $$.ASCII = true }
    | _NOCASE_      { $$.Nocase = true }
    | _FULLWORD_    { $$.Fullword = true }
    | _PRIVATE_     { $$.Private = true }
    ;


hex_modifiers
    : /* empty */
    {
      $$ = data.StringModifiers{}
    }
    | hex_modifiers hex_modifier
      {
        $$ = data.StringModifiers {
          Private: $1.Private || $2.Private,
        }
      }
    ;


hex_modifier
    : _PRIVATE_   { $$.Private = true }
    ;


identifier
    : _IDENTIFIER_
      {
        
      }
    | identifier '.' _IDENTIFIER_
      {
        
      }
    | identifier '[' primary_expression ']'
      {
        
      }

    | identifier '(' arguments ')'
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
    | arguments_list ',' expression
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
    | primary_expression _ICONTAINS_ primary_expression
      {
        
      }
    | primary_expression _STARTSWITH_ primary_expression
      {
        
      }
    | primary_expression _ISTARTSWITH_ primary_expression
      {
        
      }
    | primary_expression _ENDSWITH_ primary_expression
      {
        
      }
    | primary_expression _IENDSWITH_ primary_expression
      {
        
      }
    | primary_expression _IEQUALS_ primary_expression
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
    | _FOR_ for_expression for_iteration ':' '(' boolean_expression ')'
      {
        
      }
    | for_expression _OF_ string_set
      {
        
      }
    | for_expression _OF_ rule_set
      {
        
      }
    | primary_expression '%' _OF_ string_set
      {
        
      }
    | primary_expression '%' _OF_ rule_set
      {
        
      }
    | for_expression _OF_ string_set _IN_ range
      {

      }
    | _NOT_ boolean_expression
      {
        
      }
    | _DEFINED_ boolean_expression
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
    |'(' expression ')'
      {
        
      }
    ;


for_iteration
    : for_variables _IN_ iterator
      {

      }
    | _OF_ string_iterator
      {

      }
    ;


for_variables
    : _IDENTIFIER_
      {

      }
    | for_variables ',' _IDENTIFIER_
      {

      }
    ;


iterator
    : identifier
      {

      }
    | integer_set
      {

      }
    ;


integer_set
    : '(' integer_enumeration ')'  { }
    | range                        { }
    ;


range
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {
        
      }
    ;


integer_enumeration
    : primary_expression
      {
        
      }
    | integer_enumeration ',' primary_expression
      {
        
      }
    ;


string_iterator
    : string_set
      {

      }
    ;


string_set
    : '('
      {
        
      }
      string_enumeration ')'
    | _THEM_
      {
        
      }
    ;


string_enumeration
    : string_enumeration_item
    | string_enumeration ',' string_enumeration_item
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {

      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        
      }
    ;


rule_set
    : '(' rule_enumeration ')'
      {

      }
    ;


rule_enumeration
    : rule_enumeration_item
      {

      }
    | rule_enumeration ',' rule_enumeration_item
      {

      }
    ;


rule_enumeration_item
    : _IDENTIFIER_
      {

      }
    | _IDENTIFIER_ '*'
      {

      }
    ;


for_expression
    : primary_expression
    | for_quantifier
      {
        
      }
    ;


for_quantifier
    : _ALL_
      {

      }
    | _ANY_
      {

      }
    | _NONE_
      {

      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
        
      }
    | _FILESIZE_
      {
        
      }
    | _ENTRYPOINT_
      {
        
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
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
    | _STRING_COUNT_ _IN_ range
      {
        
      }
    | _STRING_COUNT_
      {
        
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        
      }
    | _STRING_OFFSET_
      {
        
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
        
      }
    | _STRING_LENGTH_
      {
        
      }
    | identifier
      {
        
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
        
      }
    | primary_expression '+' primary_expression
      {
        
      }
    | primary_expression '-' primary_expression
      {
        
      }
    | primary_expression '*' primary_expression
      {
        
      }
    | primary_expression '\\' primary_expression
      {
        
      }
    | primary_expression '%' primary_expression
      {
        
      }
    | primary_expression '^' primary_expression
      {
        
      }
    | primary_expression '&' primary_expression
      {
        
      }
    | primary_expression '|' primary_expression
      {
        
      }
    | '~' primary_expression
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
