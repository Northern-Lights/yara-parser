rule regex {
strings:
    $r1 = /one regex/
condition:
    $r1
}