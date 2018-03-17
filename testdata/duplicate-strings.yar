rule dup {
strings:
    $s1 = "abc"
    $s1 = "def"
condition:
    any of them
}
