include "./true.yar"

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

rule HEX_STRING {
strings:
    $h1 = {01 23 45 67 89 ab}
    $h2 = {cd ef 01 23 45 67}
condition:
    any of ($h*)
}

rule REGEX1 {
strings:
    $r1 = /first regex/
condition:
    $r1
}

rule REGEX2 {
strings:
    $r1 = /regex with mod i/i
    $r2 = /regex with mod s/s
condition:
    $r1
    or $r2
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

rule TAGS : tag1 tag2 tag3 {
condition:
    true
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

rule XOR {
strings:
    $xor1 = "xor!" xor
    $xor2 = "xor?" wide fullword xor
    $no_xor1 = "no xor :(" wide
    $no_xor2 = "no xor >:(" ascii nocase
    $no_xor3 = /xor_/
condition:
    any of them
}

rule XOR_RANGE {
strings:
    $xor1 = "xor!" xor(0)
    $xor2 = "xor?" ascii xor(0x5d)
    $xor3 = "^xor_$!" xor(0xde-0xff)
    $xor4 = "xor?" xor(132-0xff) private
    $no_xor1 = "no xor :(" wide
    $no_xor2 = "no xor >:(" ascii nocase
    $no_xor3 = /xor_/ ascii
condition:
    any of them
}

rule PRIVATE_STRING {
strings:
    $private1 = "private!" private
    $private2 = "private?" wide private
    $private3 = /private_/ wide nocase private
    $no_private1 = "no private :(" wide xor
    $no_private2 = "no private >:(" ascii nocase
condition:
    all of them
}

rule BASE64_NO_ALPHABET {
strings:
  $s1 = "abcdefg" base64
condition:
  any of them
}

rule BASE64_ALPHABET {
strings:
  $s1 = "abcdefg" base64("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
condition:
  any of them
}

rule BASE64WIDE_NO_ALPHABET {
strings:
  $s1 = "abcdefg" base64wide
condition:
  any of them
}

rule BASE64WIDE_ALPHABET {
strings:
  $s1 = "abcdefg" base64wide("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
condition:
  any of them
}

rule STRINGS_SET_IN_RANGE {
strings:
  $x1 = {0d 0a 0d 0a 0d 0a}
condition:
  uint16(0) != 0x5a4d and uint32(0) != 0xaabbccdd and filesize < 1MB and #x1 in (0..100) > 10
}

private rule DependencyRule_1 {
strings:
  $CU_1 = {aabb??aabbccddeeff??aabbccdd}
  $CU_2 = {aabb??a?9900aabbccddeeff??a?aabbccddeeff}
  $PD_1 = {aabb??aabbccddeeff??aabbccddeeff??112233445566??001122334455??445566778899}
  $PD_2 = {aabb??aabbccddeeff??aabbccddeeff??112233445566??001122334455??445566778899}
condition:
  any of ($CU*) and any of ($PD*)
}

private rule DependencyRule_2 {
strings:
  $CU_1 = {aabb??aabbccddeeff??aabbccdd}
  $CU_2 = {aabb??a?9900aabbccddeeff??a?aabbccddeeff}
  $PD_1 = {445566778899??aabbccddeeff??aabbccddeeff??112233445566??001122334455??aabb}
  $PD_2 = {445566778899??aabbccddeeff??aabbccddeeff??112233445566??001122334455??aabb}
condition:
  any of ($CU*) and any of ($PD*)
}

rule ANY_OF_RULES_SET {
condition:
  filesize < 20KB and any of (DependencyRule*)
}

rule ANY_OF_STRINGS_SET {
strings:
  $hex_1 = { aa bb e0 e8 ?? ?? ?? ?? aa 45 fc fc dd 0a ee d1 }
  $hex_2 = { 66 cc 00 00 00 66 aa }
  $h1 = "http://" xor
  $h2 = "https://" xor
condition:
  (uint16(0) == 0x5A4D and uint32(uint32(0xFF)) == 0x00001111) and
  (
    $hex_1 and $hex_2
  ) or
  (
    for any section in pe.sections : 
    (
      section.name == ".rsrc" and
      any of ($h*)
    ) and
    $hex_2
  )
}

rule IN_DOTDOT_RANGE {
strings:
  $hexstr = {aa 33 cc 88 4c 24 08 8d 40 11}
condition:
  uint16(0) == 0x5A4D and uint32(uint32(0x33)) == 0x1325 and
  for any i in (0..pe.number_of_sections-1): 
  (
    pe.sections[i].name == "SECNAME" and $hexstr at pe.sections[i].raw_data_offset
  )
}

rule ANY_IN_DOTDOT_RANGE {
strings:
  $s1 = "This program"
  $s2 = "Require Windows"
condition:
  (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00001111) and
  not any of ($s*) in (0x01 .. uint32(0x11))
}

rule DEFINED_NOT_DEFINED {
condition:
  defined pe.checksum or not defined pe.characteristics
}

rule STARTS_WITH {
condition:
  pe.sections[i].name startswith "abc"
}

rule ENDS_WITH {
condition:
  pe.sections[i].name endswith "abc"
}

rule ICONTAINS {
condition:
  pe.sections[i].name icontains "abc"
}

rule ISTARTS_WITH {
condition:
  pe.sections[i].name istartswith "abc"
}

rule IENDS_WITH {
condition:
  pe.sections[i].name iendswith "abc"
}

rule IEQUALS {
condition:
  pe.sections[i].name iequals "abc"
}

rule NONE {
strings:
  $ = "abc"
condition:
  none of them
}