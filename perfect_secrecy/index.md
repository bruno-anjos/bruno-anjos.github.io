# CSAW 2020 Qualifiers - perfect_secrecy


The challenge goes as follows:

> Alice sent over a couple of images with sensitive information to Bob, encrypted with a pre-shared key. It is the most secure encryption scheme, theoretically...

These are the two images we have access to:

{{< figure src="/image1.png">}}

{{< figure src="/image2.png">}}

One of the most secure encryption techniques that is theoretically uncrackable is One Time Pad. This technique relies completely on a single use per key rule. If this rule is broken and we XOR two encrypted contents together the encryption cancels out and we get the mix between both plaintexts.

For example taking C1 and C2 as the resulting ciphertexts from XOR'ing plaintexts P1 and P2 with the same key K we get:

> C1 = P1 ^ K
> 
> C2 = P2 ^ K
> 
> C1 ^ C2 = P1 ^ K ^ P2 ^ K

Since XOR is commutative and XOR'ing a value with itself it's always 0, and 0 is the absorbing element, the last line is equivalent to:

> P1 ^ K ^ P2 ^ K = P1 ^ P2 ^ K ^ K = P1 ^ P2 ^ 0 = P1 ^ P2

When we XOR one image to the other we get the resulting image:

{{< figure src="/result.png">}}
