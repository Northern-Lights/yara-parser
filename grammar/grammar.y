%{
package grammar

import (
    "fmt"

    "github.com/Northern-Lights/yara-parser/data"
)

var ParsedRuleset data.RuleSet

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
%token <strcnt> _STRING_COUNT_
%token <strlen> _STRING_LENGTH_
%token <stroff> _STRING_OFFSET_
%token <s> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <i64> _NUMBER_
%token <f64> _DOUBLE_
%token <s> _INTEGER_FUNCTION_
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
%right _NOT_ '~' UNARY_MINUS

%type <s>    import
%type <s>    string_enumeration_item
%type <ss>   string_enumeration
%type <ss>   tag_list
%type <ss>   tags

%type <expr>   boolean_expression
%type <expr>   condition
%type <expr>   expression
%type <expr>   primary_expression
%type <fexpr>  for_expression
%type <intset> integer_set
%type <m>      meta
%type <mod>    string_modifier
%type <mod>    string_modifiers
%type <mp>     meta_declaration
%type <mps>    meta_declarations
%type <r>      range
%type <reg>    regexp
%type <rm>     rule_modifier
%type <rm>     rule_modifiers
%type <strset> string_set
%type <yr>     rule
%type <ys>     string_declaration
%type <yss>    string_declarations
%type <yss>    strings

%union {
    f64           float64
    i64           int64
    s             string
    ss            []string

    expr          data.Expression
    fexpr         data.ForExpression
    intset        data.IntegerSet
    m             data.Metas
    mod           data.StringModifiers
    mp            data.Meta
    mps           data.Metas
    r             data.Range
    reg           regexPair
    rm            data.RuleModifiers
    strset        data.StringSet
    strcnt        data.StringCount
    strlen        data.StringLength
    stroff        data.StringOffset
    unknown       interface{}
    yr            data.Rule
    ys            data.String
    yss           data.Strings
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
          $<yr>4.Condition = $<expr>10
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
    {
      $$ = $<expr>3
    }
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
          $$ = data.Meta{$1, -$4}
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
      _REGEXP_ string_modifiers
      {
          $<ys>3.Text = $4.text

          $5.I = $4.mods.I
          $5.S = $4.mods.S

          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
      {
          $$.Type = data.TypeHexString
          $$.ID = $1
          $$.Text = $3
      }
    ;


string_modifiers
    : /* empty */                         {
      $$ = data.StringModifiers{}
    }
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
        $$ = $1
      }
    ;

expression
    : _TRUE_
      {
        $$ = data.Expression{Left:true}
      }
    | _FALSE_
      {
        $$ = data.Expression{Left:false}
      }
    | primary_expression _MATCHES_ regexp
      {
        $$ = data.Expression{Left: $1, Operator: "matches", Right: $3}
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "contains", Right: $3}
      }
    | _STRING_IDENTIFIER_
      {
        $$ = data.Expression{Left: data.TemporaryString{Identifier: $1}}
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        $$ = data.Expression{Left: data.TemporaryString{Identifier: $1}, Operator: "at", Right: $3}
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        $$ = data.Expression{Left: $1, Operator: "in", Right: $3}
      }
    | _FOR_ for_expression error
      {
        // Unused: https://github.com/Northern-Lights/yara-parser/issues/12#issuecomment-376379471
        // tldr: the "error" is used to help recover from errors, but we don't need this
      }
    | _FOR_ for_expression _IDENTIFIER_ _IN_ integer_set ':' '(' boolean_expression ')'
      {
        $$ = data.Expression{Left: data.ForInExpression{ForExpression: $2, Identifier: $3, IntegerSet: $5, Boolean: $8}}
      }
    | _FOR_ for_expression _OF_ string_set ':' '(' boolean_expression ')'
      {
        $$ = data.Expression{Left: data.ForOfExpression{ForExpression: $2, StringSet: $4, Boolean: $7}}
      }
    | for_expression _OF_ string_set
      {
        //$$ = data.Expression{Left: data.ForOfExpression{ForExpression: $2, StringSet: $4}}
      }
    | _NOT_ boolean_expression
      {
        $$ = data.Expression{Left: $2, Operator: "not"}
      }
    | boolean_expression _AND_ boolean_expression
      {
        $$ = data.Expression{Left: $1, Operator: "and", Right: $3}
      }
    | boolean_expression _OR_ boolean_expression
      {
        $$ = data.Expression{Left: $1, Operator: "or", Right: $3}
      }
    | primary_expression _LT_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "<", Right: $3}
      }
    | primary_expression _GT_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: ">", Right: $3}
      }
    | primary_expression _LE_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "<=", Right: $3}
      }
    | primary_expression _GE_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: ">=", Right: $3}
      }
    | primary_expression _EQ_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "==", Right: $3}
      }
    | primary_expression _NEQ_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "!=", Right: $3}
      }
    | primary_expression
      {
        $$ = $1
      }
    |'(' expression ')'
      {
        $$ = $2
      }
    ;


integer_set
    : '(' integer_enumeration ')'  { }
    | range                        { }
    ;


range
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {
        $$ = data.Range{From: $2, To: $4}
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


string_set
    : '(' string_enumeration ')'
      {
        $$ = data.StringSet{Array: $2}
      }
    | _THEM_
      {
        $$ = data.StringSet{Keyword: data.Keyword{Name: "them"}}
      }
    ;


string_enumeration
    : string_enumeration_item
      {
      $$ = []string{$1}
      }
    | string_enumeration ',' string_enumeration_item
      {
      $$ = append($1, $3)
      }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
      $$ = $1
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
      $$ = $1        
      }
    ;


for_expression
    : primary_expression
      {
        $$ = data.ForExpression{Expression: $1}
      }
    | _ALL_
      {
        $$ = data.ForExpression{Keyword: data.Keyword{Name: "all"}}
      }
    | _ANY_
      {
        $$ = data.ForExpression{Keyword: data.Keyword{Name: "any"}}
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
        $$ = $2
      }
    | _FILESIZE_
      {
        $$ = data.Expression{Left: data.Keyword{Name: "filesize"}}
      }
    | _ENTRYPOINT_
      {
        $$ = data.Expression{Left: data.Keyword{Name: "entrypoint"}}
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
      {
        // TODO: document custom operator
        $$ = data.Expression{Left: $1, Operator: "integer_function", Right: $3}
      }
    | _NUMBER_
      {
        $$ = data.Expression{Left: $1}
      }
    | _DOUBLE_
      {
        $$ = data.Expression{Left: $1}
      }
    | _TEXT_STRING_
      {
        $$ = data.Expression{Left: $1}
      }
    | _STRING_COUNT_
      {
        $$ = data.Expression{Left: $1}
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        $1.Index = $3
        $$ = data.Expression{Left: $1}
      }
    | _STRING_OFFSET_
      {
        $$ = data.Expression{Left: $1}
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
        $1.Index = $3
        $$ = data.Expression{Left: $1}
      }
    | _STRING_LENGTH_
      {
        $$ = data.Expression{Left: $1}
      }
    | identifier
      {
        $$ = data.Expression{Left:$<s>1}
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
        $$ = data.Expression{Left:$2, Operator: "unary-minus"}
      }
    | primary_expression '+' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "+", Right: $3}
      }
    | primary_expression '-' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "-", Right: $3}
      }
    | primary_expression '*' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "*", Right: $3}
      }
    | primary_expression '\\' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "\\", Right: $3}
      }
    | primary_expression '%' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "%", Right: $3}
      }
    | primary_expression '^' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "^", Right: $3}
      }
    | primary_expression '&' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "&", Right: $3}
      }
    | primary_expression '|' primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "|", Right: $3}
      }
    | '~' primary_expression
      {
        $$ = data.Expression{Left: $2, Operator: "~"}
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: "<<", Right: $3}
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
        $$ = data.Expression{Left: $1, Operator: ">>", Right: $3}
      }
    | regexp
      {
        $$ = data.Expression{Left: $1}
      }
    ;

%%
