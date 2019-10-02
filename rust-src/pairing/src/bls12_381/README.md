# BLS12-381

This is an implementation of the BLS12-381 pairing-friendly elliptic curve construction.

## BLS12 Parameterization

BLS12 curves are parameterized by a value *x* such that the base field modulus *q* and subgroup *r* can be computed by:

* q = (x - 1)<sup>2</sup> ((x<sup>4</sup> - x<sup>2</sup> + 1) / 3) + x
* r = (x<sup>4</sup> - x<sup>2</sup> + 1)

Given primes *q* and *r* parameterized as above, we can easily construct an elliptic curve over the prime field F<sub>*q*</sub> which contains a subgroup of order *r* such that *r* | (*q*<sup>12</sup> - 1), giving it an embedding degree of 12. Instantiating its sextic twist over an extension field F<sub>q<sup>2</sup></sub> gives rise to an efficient bilinear pairing function between elements of the order *r* subgroups of either curves, into an order *r* multiplicative subgroup of F<sub>q<sup>12</sup></sub>.

In zk-SNARK schemes, we require F<sub>r</sub> with large 2<sup>n</sup> roots of unity for performing efficient fast-fourier transforms. As such, guaranteeing that large 2<sup>n</sup> | (r - 1), or equivalently that *x* has a large 2<sup>n</sup> factor, gives rise to BLS12 curves suitable for zk-SNARKs.

Due to recent research, it is estimated by many that *q* should be approximately 384 bits to target 128-bit security. Conveniently, *r* is approximately 256 bits when *q* is approximately 384 bits, making BLS12 curves ideal for 128-bit security. It also makes them ideal for many zk-SNARK applications, as the scalar field can be used for keying material such as embedded curve constructions.

Many curves match our descriptions, but we require some extra properties for efficiency purposes:

* *q* should be smaller than 2<sup>383</sup>, and *r* should be smaller than 2<sup>255</sup>, so that the most significant bit is unset when using 64-bit or 32-bit limbs. This allows for cheap reductions.
* F<sub>q<sup>12</sup></sub> is typically constructed using towers of extension fields. As a byproduct of [research](https://eprint.iacr.org/2011/465.pdf) for BLS curves of embedding degree 24, we can identify subfamilies of BLS12 curves (for our purposes, where x mod 72 = {16, 64}) that produce efficient extension field towers and twisting isomorphisms.
* We desire *x* of small Hamming weight, to increase the performance of the pairing function.

## BLS12-381 Instantiation

The BLS12-381 construction is instantiated by `x = -0xd201000000010000`, which produces the largest `q` and smallest Hamming weight of `x` that meets the above requirements. This produces:

* q = `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` (381 bits)
* r = `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` (255 bits)

Our extension field tower is constructed as follows:

1. F<sub>q<sup>2</sup></sub> is constructed as F<sub>q</sub>(u) / (u<sup>2</sup> - β) where β = -1.
2. F<sub>q<sup>6</sup></sub> is constructed as F<sub>q<sup>2</sup></sub>(v) / (v<sup>3</sup> - ξ) where ξ = u + 1
3. F<sub>q<sup>12</sup></sub> is constructed as F<sub>q<sup>6</sup></sub>(w) / (w<sup>2</sup> - γ) where γ = v

Now, we instantiate the elliptic curve E(F<sub>q</sub>) : y<sup>2</sup> = x<sup>3</sup> + 4, and the elliptic curve E'(F<sub>q<sup>2</sup></sub>) : y<sup>2</sup> = x<sup>3</sup> + 4(u + 1).

The group G<sub>1</sub> is the *r* order subgroup of E, which has cofactor (x - 1)<sup>2</sup> / 3. The group G<sub>2</sub> is the *r* order subgroup of E', which has cofactor (x<sup>8</sup> - 4x<sup>7</sup> + 5x<sup>6</sup> - 4x<sup>4</sup> + 6x<sup>3</sup> - 4x<sup>2</sup> - 4x + 13) / 9.

### Generators

The generators of G<sub>1</sub> and G<sub>2</sub> are computed by finding the lexicographically smallest valid `x`-coordinate, and its lexicographically smallest `y`-coordinate and scaling it by the cofactor such that the result is not the point at infinity.

#### G1

```
x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
```

#### G2

```
x = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758*u + 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
y = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582*u + 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
```

### Serialization

* Fq elements are encoded in big-endian form. They occupy 48 bytes in this form.
* Fq2 elements are encoded in big-endian form, meaning that the Fq element c0 + c1 * u is represented by the Fq element c1 followed by the Fq element c0. This means Fq2 elements occupy 96 bytes in this form.
* The group G1 uses Fq elements for coordinates. The group G2 uses Fq2 elements for coordinates.
* G1 and G2 elements can be encoded in uncompressed form (the x-coordinate followed by the y-coordinate) or in compressed form (just the x-coordinate). G1 elements occupy 96 bytes in uncompressed form, and 48 bytes in compressed form. G2 elements occupy 192 bytes in uncompressed form, and 96 bytes in compressed form.

The most-significant three bits of a G1 or G2 encoding should be masked away before the coordinate(s) are interpreted. These bits are used to unambiguously represent the underlying element:

* The most significant bit, when set, indicates that the point is in compressed form. Otherwise, the point is in uncompressed form.
* The second-most significant bit indicates that the point is at infinity. If this bit is set, the remaining bits of the group element's encoding should be set to zero.
* The third-most significant bit is set if (and only if) this point is in compressed form _and_ it is not the point at infinity _and_ its y-coordinate is the lexicographically largest of the two associated with the encoded x-coordinate.

## Hashing to G1

Hasing bytestrings to G1 is implemented as specified by the indirect approach (section 4) and construction #2 of section 5 of the paper https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2019/403&version=20190426:065120&file=403.pdf

### Testing SWU

The SWU map is tested using 4 test cases that covers the cases generated by the two conditionals g(X_0(t))^((p-1)/2) == 1 and sign(t) == Plus

The test cases are generated using a sage implementation of the SWU map which is

```
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
F = GF(p)
a1 = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
b1 = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0


def sgn(t):
    if Integer(t) > (p-1)/2:
        return -1
    else:
        return 1


def swu(t):
    t = F(t)
    a = F(a1)
    b = F(b1)
    if (t==1 or t==0 or t==-1):
        return (0,1,0)
    X0t = (-b/a)*(1 + (1/(t^4 - t^2)))
    gX0t = X0t^3 + a*X0t + b
    if (gX0t^((p-1)/2) == F(1)):
        return (X0t, sgn(t)*gX0t^((p+1)/4), 1)
    else:
        X1t = -1*(t^2)*X0t
        gX1t = X1t^3 + a*X1t + b
        return (X1t, sgn(t)*gX1t^((p+1)/4), 1)
```

This generates testcases

```
t0 = 0x969b9cc7315e4ac2371da3f9c675eed35b6384ca795d17d8dd8e12da6b833c01c1c6afa860d860060020964873e1264
swu(t0) = (
    0x8968f732dbad02a9b2a0d54346a068e6aaf1de330a9d09e816547444f05b17d0df13adc16356f5cbcd2ceaab47d55c4,
    0x11ec46738b7631c340bedd967d35f68873eb067edfbfc9bf725a3823e2850722830ea0c294779dff8ad0b1aed441d0a2,
    0x1)
    
t1 = 0x128ca46d7ba7268dda23e2c7bb0bbb1bb32802e3e19c195ecd9109b45f9ffc633e8f682b456faae4067f6840d661620c
swu(t1) = (
    0x888d8e87baad9c27bfba7a144a45cb9093da5b2b13be8b430ccb4314efb43a448c4e273b7d14a482e079116e9e85d2d,
    0xcd6450cd98477ae7ed9889b59a528e2d05182042257d2b41fe00315fce28200ea14b5d50f14b7906da0f00e3a3e3b53,
    0x1)
    
t2 = 0x154ed432ba8d7d846c12f670b2f9ee68703b9270167358189de20ab9ee5fc81c6dd4649aa57b7d28414831e9ea6a1c7c
swu(t2) = (
    0x537d5f03530d09edfe5627c6c1d90796505cb2ada43ef113c8ca5b097e3ee74b97f4768c2944bba540b426a6cc9b007,
    0x14e44b5a03cfcc14869b5bbb33801bf4149fa85fe17bcebcac5abeefae61495e1c67182a42ad8600e15bdfb065c828d9,
    0x1)
    
t3 = 0xbdb5243c7b6b15dbe4a8fd0901af2cf8a297a516eeaa6ed685f682eb98311989bc64f8b0c846a167575ab9f2cdc376
swu(t3) = (
    0x646144588fd3473b16ee9f40dd57aa542f8d90c54684e6f69fdceaaf9728fd88f8455f1f235b2ceae13df3509345c9b,
    0xc89264ed2bf4ee21c08615aaa8389683dec01a1567cd3d3cfbb85cc60d0004f3c6441b5575e005964ef53cc0839aa33,
    0x1)
```

### Testing 11-isogeny

The 11-isogeny is tested using 2 test cases. The test cases are pairs ((x,y),(x',y')), where (x,y) is on the 11-isogenous curve to the curve of G1 and (x',y') is the 11-isogeny applied to (x,y).

The isogeny is computed using sage with the following code

```
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
F = GF(p)

a1 = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
b1 = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
k1 = [ 0x133341fb0962a34cb0504a9c4fada0a5090d38679b4c040d5d1c3afb023a3409fcc0815fea66d8b02bbef9c8b5a66e07
, 0x264908af037bcede00d054cf5d4775e83eb6cf63c76b969f8ed174fb59fcff78d201f46f6cfc4ed6552e59ce75177b0
, 0x1335c502c1f54c49aceea65e87fd7203ba0f626f305fc0cfd606a5dae9f3c8e81a4b3b69600129fabd307c69bf319d39
, 0x94440f65f408a6e930e16e3e92dd17bf60d6e9679a8d3d58593de55ac23703042d609537eb3549aac234d896ca82944
, 0x4afe09d5cf4956a23b6b71f59d2b3407b415a774b7be81bbb6fa99cbc798e0ac98ba725a5bc328016b1c268b4766e85
, 0x1
]
Ell = EllipticCurve(F, [0, 4])
EllP = EllipticCurve(F, [a1, b1])
iso11 = EllipticCurveIsogeny(EllP, k1, codomain=Ell, degree=11)
iso11.switch_sign()
```

The test cases are:

```
x1 = 231676323333219032364207663160931012408135689080701790049416995747433764605315759399331076266193515570430995049583
y1 = 1679701275502850236404761224635518110616107305447740765847030766801057551645601784778242705363960817147253464979660

x1' = 2462470316687406725265935944033330307865993658929330879249576046234792668690184598793893670391772666445389495997970
y1' = 1305585544177362738895827194786305935351300563185311476107805270117356948076235166602872188538678439100090683175388


x2 = 200672990962149954463803146802967864720527670550092954518341273224587459684808873511630728943600649771874365573754
y2 = 3771658320633238787764443471835928880231542729858183816905716275784304196017898359904922975462921081984123896844037
  
x2' = 751464328052491409370915162588147071834631858446608699879213045826820895244140093535995699583970173378180279055064
y2' = 3766342793094137890660475956436782650146903774069499310802413350809867070503035142752911481430587061848145471128246
```

For the second test case, we transform the point to an equivalent point in jacobian projective coordinates before applying the isogeny, testing that this doesn't change the result of applying the isogeny

