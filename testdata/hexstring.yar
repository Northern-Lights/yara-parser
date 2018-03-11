rule hexstring {
strings:
    $h1 = {01 12 23 34 56 67 78 89 9a ab bc cd de ef }
condition:
    $h1
}