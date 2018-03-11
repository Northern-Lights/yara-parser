import "pe"

rule is_pe : pe_tag {
meta:
    description = "Uses pe module to determine if file is PE"
strings:
    $s1 = "MZ"
condition:
    $s1 at 0 and pe.imports("kernel32.dll")
}