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

/* Lexical analyzer for YARA */

%{

// Necessary types for flexgo
type YYtype int
type YYcontext interface{}

// Global YYtext - each action sets this to the current yytext
var YYtext string

YY_USER_ACTION(
  YYtext = string(yytext)
)

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option noinput
%option nounput
%option never-interactive
%option yylineno
%option prefix="yara_yy"
%option outfile="lex.yy.go"

%option verbose
%option warn

%x str
%x regexp
%x include
%x comment

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]
octdigit      [0-7]

%%

".."                    { return _DOT_DOT_;     }
"<"                     { return _LT_;          }
">"                     { return _GT_;          }
"<="                    { return _LE_;          }
">="                    { return _GE_;          }
"=="                    { return _EQ_;          }
"!="                    { return _NEQ_;         }
"<<"                    { return _SHIFT_LEFT_;  }
">>"                    { return _SHIFT_RIGHT_; }
"private"               { return _PRIVATE_;     }
"global"                { return _GLOBAL_;      }
"rule"                  { return _RULE_;        }
"meta"                  { return _META_;        }
"strings"               { return _STRINGS_;     }
"ascii"                 { return _ASCII_;       }
"wide"                  { return _WIDE_;        }
"fullword"              { return _FULLWORD_;    }
"nocase"                { return _NOCASE_;      }
"condition"             { return _CONDITION_;   }
"true"                  { return _TRUE_;        }
"false"                 { return _FALSE_;       }
"not"                   { return _NOT_;         }
"and"                   { return _AND_;         }
"or"                    { return _OR_;          }
"at"                    { return _AT_;          }
"in"                    { return _IN_;          }
"of"                    { return _OF_;          }
"them"                  { return _THEM_;        }
"for"                   { return _FOR_;         }
"all"                   { return _ALL_;         }
"any"                   { return _ANY_;         }
"entrypoint"            { return _ENTRYPOINT_;  }
"filesize"              { return _FILESIZE_;    }
"matches"               { return _MATCHES_;     }
"contains"              { return _CONTAINS_;    }
"import"                { return _IMPORT_;      }

"("                     { return _LPAREN_; }
")"                     { return _RPAREN_; }
"{"                     { return _LBRACE_; }
"}"                     { return _RBRACE_; }
"["                     { return _LBRACKET_; }
"]"                     { return _RBRACKET_; }
":"                     { return _COLON_; }
"."                     { return _DOT_; }
"="                     { return _EQUAL_SIGN_; }
","                     { return _COMMA_; }
"%"                     { return _PERCENT_; }
"|"                     { return _PIPE_; }
"^"                     { return _CARAT_; }
"&"                     { return _AMP_; }
"+"                     { return _PLUS_; }
"-"                     { return _MINUS_; }
"*"                     { return _ASTERISK_; }
"\\"                    { return _BACKSLASH_; }
"~"                     { return _TILDE_; }

"/*"                    { BEGIN (comment);       }
<comment>"*/"           { BEGIN (INITIAL);       }
<comment>(.|\n)         { /* skip comments */   }


"//"[^\n]*              { /* skip single-line comments */ }


include[ \t]+\"         {
                          BEGIN (include);
                        }


<include>[^\"]+         { }


<include>\"             { BEGIN (INITIAL);}


<<EOF>> { }


$({letter}|{digit}|_)*"*"  {
  return _STRING_IDENTIFIER_WITH_WILDCARD_;
}


$({letter}|{digit}|_)*  {
  return _STRING_IDENTIFIER_;
}


#({letter}|{digit}|_)*  {
  return _STRING_COUNT_;
}


@({letter}|{digit}|_)*  {
  return _STRING_OFFSET_;
}


!({letter}|{digit}|_)*  {
  return _STRING_LENGTH_;
}


u?int(8|16|32)(be)? {
  return _INTEGER_FUNCTION_;
}


({letter}|_)({letter}|{digit}|_)*  {
  return _IDENTIFIER_;
}


{digit}+(MB|KB){0,1}  {
  return _NUMBER_;
}

{digit}+"."{digit}+  {
  return _DOUBLE_;
}

0x{hexdigit}+  {
  return _NUMBER_;
}

0o{octdigit}+  {
  return _NUMBER_;
}


<str>\"   {     /* saw closing quote - all done */

  BEGIN (INITIAL);

  return _TEXT_STRING_;
}


<str>\\t   {
}


<str>\\n   {
}


<str>\\\"   {
}


<str>\\\\   {
}


<str>\\x{hexdigit}{2} {
}


<str>[^\\\n\"]+   { }


<str>\n  {
  /* syntax_error("unterminated string"); */
}


<str>\\(.|\n) {
  /* syntax_error("illegal escape sequence"); */
}


<regexp>\/i?s?  {
  BEGIN (INITIAL);
  return _REGEXP_;
}


<regexp>\\\/  {
}


<regexp>\\. {
}


<regexp>[^/\n\\]+ { }


<regexp>\n  {
  /* syntax_error("unterminated regular expression"); */
}


\"  {
  BEGIN (str);
}


"/"  {
  BEGIN (regexp);
}


\{(({hexdigit}|[ \-|\?\[\]\(\)\n\r\t]|\/\*[^*]*\*\/)+|\/\/.*)+\}  {
  // Match hex-digits with whitespace or comments. The latter are stripped
  // out by hex_lexer.l

  return _HEX_STRING_;
}


[ \t\r\n]   /* skip whitespace */

.   {

  /*
  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    return yytext[0];
  }
  else
  {
    syntax_error("non-ascii character");
  }
  */
}

%%
