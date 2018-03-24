rule FOR {
strings:
    $s1 = "abc"
condition:
    for any i in (1..#s1) :
    (
        @s1[i] > 20
    )
}
