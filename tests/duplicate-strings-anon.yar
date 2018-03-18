rule dup {
strings:
    $ = "abc"
    $ = "def"
condition:
    any of them
}
