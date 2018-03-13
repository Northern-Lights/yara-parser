include "../others.yar"

import "pe"
import "math"

rule BASIC_BOOL {
condition:
    true
}

rule BASIC_BOOL2 {
condition:
    false
}

rule STRING1 {
strings:
    $s1 = "ABCDEFG"
condition:
    $s1
}

rule STRING2 {
strings:
    $s1 = "ABCDEFG"
    $s2 = "HIJKLMN"
condition:
    $s1 or $s2
}

rule TAG : tag1 {
condition:
    true
}

rule TAG_STRING : tag2 {
strings:
    $s1 = "ABCDEFG"
condition:
    $s1
}

global rule GLOBAL {
condition:
    true
}

private rule PRIVATE {
condition:
    true
}

rule META {
meta:
    meta_str = "string metadata"
    meta_int = 42
    meta_neg = -42
    meta_true = true
    meta_false = false
condition:
    true
}