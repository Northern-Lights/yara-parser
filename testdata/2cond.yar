rule two_conditions {
strings:
    $s1 = "one string"
condition:
    $s1 and true
    and not false
}
