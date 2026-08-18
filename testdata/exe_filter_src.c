/* Payload source for the x86 filter fixture.
 *
 * The RAR5 compressor applies its x86 branch filter only when a block's
 * statistics look like real machine code, so a synthetic byte pattern does not
 * trip it. This generates many small functions that call each other, producing
 * a dense field of genuine relative CALL instructions once compiled. */

#define F(n)                                                                   \
  int f##n(int x);                                                             \
  int g##n(int x) { return f##n(x) + n; }                                      \
  int f##n(int x) { return x * n + g##n(x % 7) - n; }

#define F10(n)                                                                 \
  F(n##0) F(n##1) F(n##2) F(n##3) F(n##4) F(n##5) F(n##6) F(n##7) F(n##8)      \
  F(n##9)

#define F100(n)                                                                \
  F10(n##0) F10(n##1) F10(n##2) F10(n##3) F10(n##4) F10(n##5) F10(n##6)        \
  F10(n##7) F10(n##8) F10(n##9)

F100(1)
F100(2)
F100(3)
F100(4)
F100(5)

int main(int argc, char **argv) {
  int acc = argc;
  acc += f100(acc) + f200(acc) + f300(acc) + f400(acc) + f500(acc);
  acc += g123(acc) + g234(acc) + g345(acc) + g456(acc);
  return acc & 1;
}
