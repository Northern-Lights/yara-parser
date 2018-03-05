%{

%}


%expect 1   // expect 1 shift/reduce conflicts

// Uncomment this line to print parsing information that can be useful to
// debug YARA's grammar.

// %debug

%name-prefix "yara_yy"
%pure-parser
%parse-param {void *yyscanner}
%parse-param {YR_COMPILER* compiler}
%lex-param {yyscan_t yyscanner}
%lex-param {YR_COMPILER* compiler}

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
  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;
  YR_RULE*        rule;
}


%%

rules
    : /* empty */
    | rules rule
    | rules import
    | rules error rule      /* on error skip until next rule..*/
    | rules error import    /* .. or import statement */
    | rules error "include" /* .. or include statement */
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
      tags '{' meta strings
      {
       
      }
      condition '}'
      {
        
      }
    ;


meta
    : /* empty */
      {
        
      }
    | _META_ ':' meta_declarations
      {
        
      }
    ;


strings
    : /* empty */
      {
        
      }
    | _STRINGS_ ':' string_declarations
      {
        
      }
    ;


condition
    : _CONDITION_ ':' boolean_expression
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
    | ':' tag_list
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
    : _IDENTIFIER_ '=' _TEXT_STRING_
      {
        
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
        
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
        
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
        
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
        
      }
    ;


string_declarations
    : string_declaration                      { }
    | string_declarations string_declaration  { }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
      {
        
      }
      _TEXT_STRING_ string_modifiers
      {
        
      }
    | _STRING_IDENTIFIER_ '='
      {
        
      }
      _REGEXP_ string_modifiers
      {
        
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
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
      '(' boolean_expression ')'
      {
        
      }
    | _FOR_ for_expression _OF_ string_set ':'
      {
        
      }
      '(' boolean_expression ')'
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
    |'(' expression ')'
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
