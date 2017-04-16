// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { deriveKey } from "./pbkdf2";
import { SHA256 } from "@stablelib/sha256";
import { SHA224 } from "@stablelib/sha224";
import { SHA512 } from "@stablelib/sha512";
import { encode, decode, decodedLength } from "@stablelib/base64";

const testVectors256 = [
    [
        "",
        "",
        "6Gxh3R2qsnY="
    ], [
        "FA==",
        "+g==",
        "lRz9af3q4+L9"
    ], [
        "V1A=",
        "tsk=",
        "+6NNiE+6UpfPtQ=="
    ], [
        "3LwS",
        "Fk7U",
        "u7xMnN/jv6i9f64="
    ], [
        "S8OTug==",
        "CQcgCw==",
        "SbDhhDZLk9KezPI4"
    ], [
        "+Ok30Ow=",
        "v5LEsRc=",
        "ajo+jYt9qbpp288htQ=="
    ], [
        "ZNwjYqYT",
        "NnyKUIPe",
        "U7CeKVqglu0hmouP5fE="
    ], [
        "vBjwaNjKpA==",
        "o5WDQUSkHA==",
        "2rzvGBBT5sKW9P55hpeD"
    ], [
        "1n0ogha/mmU=",
        "725S1rlL4hk=",
        "5V9yixMKnH4FX2lEccCaNw=="
    ], [
        "tSTmoYmrdmyU",
        "w4ajBeOTnXUZ",
        "+5/rANsgSjvaSS7GXOgR0Ko="
    ], [
        "BqDUIQ0RTvCOLA==",
        "yn4/vu9/NNWbjQ==",
        "AkR6RJzFO2aVM5coFOVKZU0f"
    ], [
        "JWxV6+r25tb50fI=",
        "vVNX/gKjbpjpZ7c=",
        "Otrdew6kLL1fWWkMrfdz7HgOqw=="
    ], [
        "9emtTGLYiAn0X9gU",
        "yRGvB4uhHyDIr2eL",
        "JQIs/Bxp7WtFutVMehd9igTdDUg="
    ], [
        "bb2Bs1fwErzdvku3YA==",
        "S5bRxQQF9TOGutpigg==",
        "WV2mMdlu69v2I+S9ptmo/BkpmNMX"
    ], [
        "WbRDLW1xCn8txj0Ku54=",
        "5xUaeMvHqffI5W7aCdA=",
        "5TUTmhFhKtwBdgrj06uFeHzmvOT5fg=="
    ], [
        "KTtftUx5Oa5KuluWz7Ys",
        "cClzKFAavwdOVi6iNPLe",
        "H2mT3cHK3ifecaA5Rk7ZKWCjFx0NE6U="
    ], [
        "mUO+vmUvqJ0gpwtxd6WfMw==",
        "UniOUC2QPPV5Tfm+ukIv8A==",
        "+q2WH1zHQudnD4NC1JjVg8oCeFUHy8ZO"
    ], [
        "pnIr/aT5hCtAkkW87jBrPUU=",
        "T6lZl7vsizkoEiOsXTJ/uzo=",
        "XlhrzbSJpo8j1zVVyawSSSUfJgjo5W414w=="
    ], [
        "dYXNGdapOevUA8UnS5I6Mr0M",
        "k2yQ1KPAVMNNl2bbXuar56Jp",
        "F1orRWQfxzsOz02Oh90h2/MazTaghynKO0Q="
    ], [
        "NpCTGhYfPc2ptPfR7hAO2lAaEg==",
        "Lyp8aFonCRf6iZQsKsOXU0aL9w==",
        "ED0NZIkvCoZfmQwfZE3wufcTlXfi3hXkn+Xb"
    ], [
        "IZmpw7HXQtraayV+ui5SjSNHsnQ=",
        "N26dc1c3AfzDxqBPXabBqUBprCI=",
        "vmGdqjz/UpHdv+tLWriWL2fOpatxDYWB6btFgQ=="
    ], [
        "tR9fgYP/VyhKT+YaPPSfNKWjtalF",
        "pYbBkZxzZxJ1wyTsbXyZIBwhlmbG",
        "O9YQZ6LleJAZhH9ODc6Uz5NVFPxOr3Z0gXlnKB0="
    ], [
        "ogUH89CJEI9IW5mmyT32DF7UjX0dMg==",
        "PMT57o1HquqPy51I19K5rsxyHe9F6g==",
        "sfJx9gXDdlLihmDK+OOayTjXfTm5Nr6Uj5Kk30T6"
    ], [
        "DkrSbHk5ZRqCCWkgCa+RzncwjNuF+wg=",
        "WuEpubJqPVQ9znl58yuL/DgCprbX3Vw=",
        "RvnEk1/dyQsSlqzJ1YfQ0J8QtaVtXFTL2ifgYDYd4w=="
    ], [
        "GVvhhkGfDgo9TYCIkl7H4x/pzstadQRv",
        "b0VnEpFg2UwJqWBcKFxhG7USrgxttCcF",
        "vD7MvHRQNUQ9lTqfvjJ35tkEidUDl4aWQktscUYOyIc="
    ], [
        "YvUz16ZjtsevQ8F5AFVaNg0oRJJgGKKBWA==",
        "nFS5rLt5QlWJdUK9StRlrUcSqrPJxViZGw==",
        "CL5KJuNepLOv5qbxLI4GFFiXCRJ7xkmDULlwPi4dd1bo"
    ], [
        "wb09/sLlUQ/Hdwo0aM0qzv4XWk4RWJoRUGQ=",
        "q/Bee6o3DFeVsLKf8xG761EB2qdGiLiePbE=",
        "lFJORsY04pwlKFp9rNIWvfhFfgpAvkeY7xVUMPb3glZPOA=="
    ], [
        "Uu8vKzNIGguqzPywE6d7BQs7SEIV1SB9IhU1",
        "ql0FPVKGhlAylfRn4NjlErP3hZpCOQRpSryr",
        "E1UFqyWnzWTrtIWh2BV+Xu1IaZnvnxIj0u70WB5+UtYB3D4="
    ], [
        "QToa/ovxYc4uI5DzLQvcHqBifXNMz3qJ5AzHZA==",
        "vZByoKgCGbN5vO+KbL/k0LymNT1m6c5cfgAFRw==",
        "sgbkBXZO2ApSMXpJImluc5r41DOtYr9ZCgrZgwqquR8hHvL8"
    ], [
        "K2DxzDaoFwF01lPyb6/nDe6EaGjQTsD3/GSp3CI=",
        "BGdObC4K4frE6i7vjap4rqklz0fLN+hhGx5ji3E=",
        "/9ZsLHRcV3AVXR8CuZptK59+ZhalLZOa2GaoKm6gw0BkkHjd/w=="
    ], [
        "E8037QSRRGbPxbMjTUtRHVCQ+fYTvYlALZjc09OV",
        "9H9hHBKE2CzlpdQc6aK/j0XyBtX98hBCLi1O8Ltu",
        "3n79XgH7BP33oSaMKOpJb05v1bCpG4sLFcQzEt8Ux9es4hJYv1U="
    ], [
        "f2p+sH59U8QwtG4FiQNgzGQ2671TwS+Hof5uRqUsWg==",
        "Gj5YSVRlirlSru+c2fWpwdUx6Sxf8VL0StTXEWa5OQ==",
        "854TWnmqRv+cJ9KBJPK5dGftGXEIwU/fCVRpoXZjFcLPgPPDwLuR"
    ], [
        "fkRGg8uwCTvfiX9sA14qVZ5yrFFrCY+lC9FKFHjhrC8=",
        "O8LegUTxkpZZGZb6hXCIofaxsWhBNvsv1qGAavNrP1A=",
        "Np1M5gqLQz6f6nlOG5krL03uG6LT5Vdrfc1nojH1KG6x8JZ0ira5dQ=="
    ], [
        "3vJTV+4W61el8JsCbYXuTafBkKQo/SMExsC8lP6fDX9z",
        "t9cL5uSPWTApp5pe9zzXrjV/krK0ChOFE/lmfES/0DDo",
        "+h5Pvj9pcS5PujpjOQvTS/tc1eOFwpljBbq3ImdsDN9FOO+ePhJd2pc="
    ], [
        "1cF57YGRbO9pISAIzexWylPvnlgpBhEbAyZCN3IY35JXoQ==",
        "SvxD5aowxrgv84WQOtxw2ef6jpNfH0SNFy2fAhOXn2EZcA==",
        "BZwlhobXnh9SOefEuVV5OWOIrfgVBXv0ChbiY+hEjD8nGq+ZqVMbL6J2"
    ], [
        "bQkruGsJ6Ocw9cAZmh3+/IEwyrXMaFP+ZJjuX3SoeWcwcio=",
        "lUP1eINU5v1cPwzbGsShzA69wbuI+M24oMtEMq9iSp1Yhvo=",
        "oXBBQL5PVPEebP1SyYrAVGiqJVtL4cXj2nXTA7kM6YwqNa6pCz13cJSw9Q=="
    ], [
        "Qux/RldwELjguEwCGBVPkdLgzOBahgFkf2GoG1CEbDL6u5vo",
        "iRN+DmPSeESgNPag8WQXCvwH8jPjMNkLXCO6w2pRmN6ZVU0M",
        "6cGD0VZ1Wd/6WhqyCE74MuHjvmHlxTZ2wubXUk/lrHmlFBVi2gnjR6H1NrY="
    ], [
        "gDSJUD8WGVGK1W+K6JMpKxVzO4Z7D95s1DiFSyR4tlh8Q0SDPQ==",
        "kDCR4s/Umv9GU/gY0mTSTr4oDOqCut/nPJTk8LXiOoU5B76Shw==",
        "072rOKUG8oUS1HR7o04G6yK5FyuzqndqKXXiSfMOBW4W/L9zALP2lhKgEi5Y"
    ], [
        "dseAdESSkXYlORd5cPENkr7D4k+df+2MszxrwNKVuMhhND01PGw=",
        "v235GYsEetOz23hooj/mUM1oTv+p7XP2z4OE76OMnkgZn8y7k60=",
        "Eb/m7qogFgfS9rISrpre1QEmYsF5n6W8os2G+y1BSu0+e0stZ/Xk30VF1zpaLg=="
    ], [
        "eJ/LdNMpKO2HRRTve4yOR+yxgtdUIVmZ0S33g+7oON0zTYYGnAmB",
        "skLMbadBGJFowJlScPeo5qS4g+n1TZf4JTWqBnWyAIzcMEDSfPWj",
        "O6pW0fN2QgYYEzbQlcAQKYFAOXHSh+5+mYqgY+pWSCcFp9gyYn4ort3F8EVICLY="
    ], [
        "LdtNijPtKBC1EcYX/sJvs/7h+cQqRSyNNdsKk8qGBdo+KICEtHAgZQ==",
        "JOl0FbmQE6oXuxYUQXtLYOe3sZrC3A6mD2PL9f6cXiNUbLowlzaLeQ==",
        "Lka9yhDIQVS7Qt4IMC8LgiP+MehnSPFXttsVo8sWN/iMxuTQ7WQ3NMP10Ynbi+SF"
    ], [
        "uveB5elljYCtTPNAfKJbeD8XAP+DgaYjndf2R7UTuqNG924SZS0HREU=",
        "LM6JMBc9PfO9cIVzCpUohJKw7XEc93d1rIVguY6I7hpcMZOfjPmkkR8=",
        "guy/6ybZQrIkQAAru8O3Z68Kyzwb2zLWcL5nDonQffZ0SKC+Lo7HTUUEavIQ/JtYsw=="
    ], [
        "2UKb5kQNwbz/MuW/r6uxdd7ZYsA9y3I+a5l5dUSCIQBAmrU3uDLm2S1m",
        "ImSCmOAdOMLWUzxnnN4g4Sz/+GxWO1vP0LMeeqX8KxLOp3GQlPSWJwQF",
        "Qcj+g0azeh2efBsPbbCRRQOGuLMi/1L41/OZCHkyYouzJhYF973iomyqym795ctqMBw="
    ], [
        "10KTINrI6mdet+pwn0Zas5jRdt+cIHeiNP7TrVaFG4vJvQRMpw+HRavkWg==",
        "i2hKSnqQ7Su7aNQFc3aBcOWKstgZQWiviKuiZLseSUuepoeaCfXV/hbDAA==",
        "inh/6bteHkEKyjGb3vidxL4Nk7RDVx6bXUwNxk/8RgGE/8lgehrI2krgsUnH6cEooGbt"
    ], [
        "pG8XcBNId4/P94h3fO3HbwjDoP0pkwFGZpJwPO9b+wdFD85pS8s9LGNXWuo=",
        "q95x2I/8JVQUYgQa1zO4xH99gM41R/F9cY7YelyoQRfZXiqb3lROosekCNk=",
        "DFdcuaoKg6JmZ6k/y4ZSqJbgw/HPKnH8kYFGiaet0j0eSMAe62U6G0u5cDXJp0nH69NU5A=="
    ], [
        "pUpxi6kcz5cFw/6FsIU+kT4NUnpIHlZuNu9CJYXrjb5orTUKqKkonMPplDKP",
        "Jwr1eGj67XAgiujC4QYe7iKHfUVQG6KYQeQyNKWIurkWKeoq6fyXyShhsDla",
        "Cz3H22MhWxBVpIMn83cwW0VgZFOyDjGnKVbucUGjLs2+PwQJqPwx+06OILW6DeqOStc2AJE="
    ], [
        "B5sbpmhhhDhSeDhOAEeC7mP9jo3mYg/S3VUInN+NAG6l0WHVRgESyXpr6bL46g==",
        "+/3FhzzQUDTIcFAkIZgJox7Wl2yZGmfB0PfvrdI71AkXAJYWFjthFI86ufHlcw==",
        "rean1ZlhA95ydSYWKHEsDPgir/NgsYXs79ShlTMsnFxTUqZawmNmqx+k05r3fGGRH3SH19yd"
    ], [
        "RpHtUDmd/FAyBPNw8Z0XW76Tz9XWLQQbGgY/+yKmTfYjLBve/t2zMCv+tuS2C+s=",
        "4GvtC4ZfefJHUcWGGxfQuj+MqVTKb/NiodtaamS1tPhMBCwHgTRQd/AVM6fxz4Y=",
        "jZBwRsPLo0NOzG83YZzxTAMD2QIvdATiKYq0heGZKshgJrNAuHuBiZtL8qelDksJysok3ixpHg=="
    ], [
        "kAslfYWvrh7q9bnl0PwJzTF9fANch4hCOQQdNFNtygLuisGqW2qdLCUHJFDYrzFS",
        "F1oTVwTUApN1fDgH/1oLIRKZ8qF5asJLJpBTqOw6EVeI8gtam7dJzq7J4CyEu1G7",
        "x4Xtx7eq+aVwZBmWMgTEPiJKMM82m3tebuHXmMbVjX23/CaCro/wgQR8YnhN4oqOGmkQMJt2s1M="
    ],
    [
        "+pb3b4M/KlUtYJDOvz6OVKeo3RBsi7r45W7kIQvAxAQOFvuIE6o8+cFOyDaZFDgBfQ==",
        "y0GZHmxkMY8B/rj7jyZqglNd0x07gRjiLzic+/08+SP2ITKzMz7EADBlKtHJXkvv8Q==",
        "wqFlCrGXrO8DnmTtE82k6kb8DsuU3xsMUH3/UWFfHNEWbRjEixgPF0Qb0/keRTnxIaKcP/p3LoyG"
    ], [
        "FTLD4MIowdPIbylo0QHdbS8gBJWro5p3HFmxq62v5K5NwxyoB9lBt2dh/TjnJhnkhk8=",
        "xCrO8C2FDbMabBRJVw218Hp2q8UncY49Dbvauwn4CoW41rhctoDDoIuXQipgCKI939o=",
        "kSB/H7099rwExSf7gkCEBmM6xhVJWnB/BRQfV+1TYgQmIrbwDyHSxqVjlRyLN9fU6Q4OSLzZCsmyqg=="
    ], [
        "4iGsGvbc9x62oMnxV+YtiVzVlv1cFSC+Mh6w0gRIAzjr164pzhHmCarYP3Q/B/H4DY/8",
        "Ah8Tco/GPdRP0nygo9NOoZ/JR9Fh8cngRHSzRGZSzam/F7ouyUZ8ocaZhGvPDDh7J9Vg",
        "FXSnrZzjtemUTs55MQ0f75PfYYum2mv2OKAZsCXinyLRykLUhctaca7GFYLOjLdcn7z+i2ppUSr86Dc="
    ], [
        "YomFAH4DKNzFZPppBeQrahYVaN5XjoGTFNaKtY4Teg/OFvopvbqNRJTKKOjHsMkoxiI17A==",
        "HBr+MvJQfBjsIt9cFoEVBNJlOHOhAnHw40sAqvIAWq4NKBKnu82HXmrWHL9aUpGmAx7P4A==",
        "5s6QYRaXjf6n17bQTLrz+LND4slN+xkMvlYeFAiW0X+Hmz5eEm1MsUG676JfLFm3JQ4LmayMVNg5pjHd"
    ], [
        "dieCvdoP7G35R6E/6YkvykSDv9G7FDctotNDrTySUG/9n+7bvdE92LhKo0Hy4XrqjtULpKw=",
        "cEmv6VjMT9SDZ/TlC1WK5CYQ04Vxc5ESK5O7lovL3Nh9cdAVJ1RLFs49Q8YUZMSOEK1rYhU=",
        "E8qGkHephCPvBzpYKwEPLs1NVEpOVuMh1+lCoehcVCSUX71ZTJ3Lc86/8SHUuKsaFxm0YVJiJ9jccWXy/Q=="
    ], [
        "9TohEnxJLCxbI7ftJFBQka2uQFKYACT0rrVf/3V0JrdcpAVKn529Wv/o+j+6QdcZqqohnzkt",
        "yjVbhVorWxotfE5CjX66eVXZn3O7Qu9DZS36TmELyOuqRzgJ16gcrKRxxtK7uF2JhU244fBa",
        "iKMrYMVV7T2Ib5VM7E94c1rrYKn2/+e6BNzFDez9E9e1za5E+MTp0AOPpeaTuZbxP00gLkvFKvqOidGPlA4="
    ], [
        "UxqZwXrgmM/etQGlWFY7Bv6mO/FGh5YqfUfoNEKmpn80up33aLBlLR+XuQX1x1IVdUjV+qY8uQ==",
        "e8hUGukk4eCQjft650L8rTK5BhRwouoorU1DAq4yET8TPTl/bKEUX7KjO2rrQ4JBkHwqNXiZtw==",
        "KrRYCviHCB1V/74/BgHdGopcSCFkFIcyR93y/uyq/8Jr0ML3ty2EHFpd1LUbYViTzr7s0vlOPsrcaPUDdrgl"
    ], [
        "1zIR2bHKpVfCQ/qP0LDXTxUSHRnWMYKa94YSma3ztzVrASWvP23OTI2HiMrTcAh1697yXbXOPb4=",
        "NmM0u1mHCFXnuI6mI0BAQr4OuxV2llk48oQHPQeZt6kwnERKvEiHdykZIjl3DS9j3WSd0y8wI10=",
        "/J23sgkQf6+b3Hk/nqvoOAn/j5oxGCOTl22/uHzkf23sTOzsx6hLlDIxCE0PjpsupbNppqQed/pNLLtHr85BGg=="
    ], [
        "j6p36vm1fjMqmK+2mHfXDRXYRBQ4stzPVkCSzg8sTgqfuY+UeszzYXmFjMTIR74ai3VtGHY8JDal",
        "+ozWVz17oXeS905Y7trgkB3zaL8dChN3CCLwQxAj+hQo+NlA8tKGcwIxZJLXJjk8S5AUpQAiwkvc",
        "sBq1NpRYW8S1Edkd2OsKaif8+Nt2RoZvFiZjLLynBqspwPoT9U/HL2FIMukiGODemBGrlMRGh23ECu6PBr+CPVE="
    ], [
        "7PiWy+H3xtNfFofK3cQGzBDpWJrw6jBHkij+mNmi81Z33Nr62HhJhjyBiS9L/Wje9w4iEukzWN2PCw==",
        "FJdQYllYd+g6367to0mlgQJKcVpkVgL928oynIf+PixHb3fHpCaxgqfg9Gy5KHWXBVOpBF8T5W43Hg==",
        "NuukHTpVhdEigD+BmesiCR1f/EGXa2levABtgDzWKKi5U8Y4NH6cOL+kKhd0mDmO85fN8VxooDlWiGYqHLpJ0trg"
    ],
    [
        "LTejnuZAG/2+P4WZxUAadaKVmhuwZjzXBX9gmQ0zL8dGWVKQuQOuqUz5eZ9pMdIkoWkBFrjYrI0MgGo=",
        "Gwdn8SzktWO/y5HpwNvSaXU2oEZKK1cReBlZ6qch3yBnopEpmvM0Vx3EGZdbYKUN4jr6gWNeh4iA+8E=",
        "H+0pVtp+kr1EBt9zg90SkE/nuTXuSvdRPPx0Drb64femyZFZNIF+elbJFp3AZM03kh3Gy0E+Ea989AO42vCFCCSaYw=="
    ],
    [
        "brtFyf0OI2wSfsM9XznegXh9Kft8peUocTkyHVOfdUxI/KEErQmqQPthBErVOb9ekR6rU7XJ483q8shS",
        "WJxTFTGiLyKRcmz4IF/tAilzKtumiXrMuyDrbmLj+FAb920lDinWq+3fanw93/bSPSAjdXTb/ULmjCBq",
        "aMfer2J6VCVdHa7BwiUScgFehgg63MC8sxXeHvowJCFF2j5rk+e1I1Dd7StW/C35EnhhOPkul43jJanUGe50lbA4tWs="
    ], [
        "2CWmCNSkYeS82f+ztgkOVeelN4YNtF9GCHn9ObqjVz8lJSUlsaIGa+79ELTlRuvLCP65s9nbe0F5tP/Tlw==",
        "ICGZD/cwkSuxulTQJmOn1PK/wAAh8hKQqAa1NxKw8APv3wMtEgOmNGPinug9vyKqCVpUFbPG3QyYsxdagw==",
        "rl2qkUvjmeUXuXTWnZMKZvSbjiIJuMZ2qTyEwAZzAZ70dHAeCvV8yub36yEtXvCRl6Wcjbk9mf5URvEw8ONiY9twH9I/"
    ]
];

const testVectors224 = [
    [
        "",
        "",
        "zrAWDLjsMAE="
    ],
    [
        "xA==",
        "7g==",
        "BNPhO9jLkDSI"
    ],
    [
        "xMc=",
        "Obg=",
        "1QLNjmOxszs1GQ=="
    ],
    [
        "/AFt",
        "WRR9",
        "3YqPfnZ7Ha91eYg="
    ],
    [
        "UenWEA==",
        "SzkJfA==",
        "JowlSbCgPzcevMba"
    ],
    [
        "tuM+n0k=",
        "HsFOlXs=",
        "CLPt+SGe0jncSTcJ/w=="
    ],
    [
        "9+AJ3GGO",
        "cA5CwUCM",
        "T7EGWxaFI8zg8Qkdnxg="
    ],
    [
        "km9JVe5pWg==",
        "lYfEb4s/MA==",
        "WL1VD+5H6xXytMvq4DAR"
    ],
    [
        "JPg8L2l0gjc=",
        "PZ36rRtxC1c=",
        "sDthl+EFy1MVNXAu4NIXTg=="
    ],
    [
        "7x8wGI5vTt48",
        "2SG96nyWQK0b",
        "JyT/5ZqWCfGXoR4yYHK/Guk="
    ],
    [
        "ZryDMIG1Gi7sig==",
        "OUmeRDF2VP4JVg==",
        "AYMn61pzFWy/Vz9kSkEhuG9l"
    ],
    [
        "BT7as9GrFMk77jo=",
        "J+sHg5539G1w1DY=",
        "l61el7I1NlzhQc+VDl9xN4S+qg=="
    ],
    [
        "kXRIJjiR1Tw65pYT",
        "tm0csjMePKpt8ocM",
        "yqCcMDvx+IYcH4v2pF970esCjD4="
    ],
    [
        "2XyYxrpi2JHSW0styA==",
        "/zTini6/UJFLu3rq6A==",
        "LlMTbmCnEghFtCggUlynzdrSjYSO"
    ],
    [
        "8cqcGp5jksuHhr28y/Y=",
        "1wK+gl6Hlcs4nNzM5qY=",
        "sRjRaPSNuppE8VC03sPk48n0PrEzmw=="
    ],
    [
        "dVdLP57NTmMep+2HEMXY",
        "ylYStxoI0qDeNwEbpFsf",
        "Mi2WmTsmgCxxl119DJ3D7rpg1C/NwbY="
    ],
    [
        "55OO8q+KJL45U85O1hMggg==",
        "8kO+rp8nE9KFfqJ6cssPNA==",
        "OBF2h2Y2GuLqTPlmJs0LYCx7ZeWAm4ZB"
    ],
    [
        "KXfmtrBr2gKwJNwK5vzpnCE=",
        "1KUG3vXgde7jtfFb1w/xCT8=",
        "YDBbJstPueM2ukcOIlu2i7UmJizCPhE2BA=="
    ],
    [
        "A1zDet/s58oZiXb73RfjFb1L",
        "EBN7+3acfHnILssxaF7USamy",
        "gZbI3H/HNZhIPjovPC0ZX+LM3epA2SLaa+k="
    ],
    [
        "fXcWrF1HIi9z4eZOKS1E8kWIrQ==",
        "odazdygTZBjxdyOUR7IOwbAUcg==",
        "Yih3v2D74Jgij+xU1Lkv63FrpFgLDQLcatNC"
    ],
    [
        "fewpgc+7eR52qLKIEnVCLXAXpcI=",
        "Ik9kkl7ydmrA4TIp0y0maYzVWKE=",
        "X15iXDD83EpvQiPUQ4tMIYEcKXzoMr+mhGb/kw=="
    ],
    [
        "2EHCDNk4uIKlpO20c31hvjtfQl8+",
        "JsOqOI25PSWbIdwGjaph/HRNcJOJ",
        "MWQV4wfyE3CQ2ex/wgVk/EmggDIBGdwW/CAo7Qg="
    ],
    [
        "ImLLktytsmZXOorPnBRudMltA0qMfw==",
        "LBxbEdpEhluThE8oTtO7p/mxxXIirg==",
        "Ht/W6ybOa1fmR1YVIScRjL2k9SwEdOCalh4SNWlD"
    ],
    [
        "XzwEQ6PP5A4qiwSOI49nTBXRIRePUqs=",
        "4VwqJUZupQ7yQn9yeW1NuLMkncz3Hmw=",
        "HhsgiF7Q/WgdmPWIoCYOLZOPqLhDbacqGHvulCEa4g=="
    ],
    [
        "ZAvR2wQt45YL1ydxSy7f5fWhBrjRJaOb",
        "X3xzT/0ET9/kyhv2JdpnpLOvVn42IBbA",
        "gdAzeKl8hVubd9cp+Llnd9Hr8G3DHzkqWkwoKjpb7+0="
    ],
    [
        "I9JmYwnkjKLIdmw1XmhWhV0c50KMw3DjpA==",
        "MuE3nhZf0vhAOwDm3YBM8ek035UZduE4gA==",
        "p37W4aYafgG4cXjVA44VdAF1UrhHSD4UbiLh7KveVY4S"
    ],
    [
        "qSaMfCzsUQ7huoxX3BgkJCVPbm2fRGxdRNU=",
        "oNjwAMFL/8MMYXIWVLyPFvWOHr6HxI1kQWw=",
        "klNyXmH54eaoKsS6wYLWpMpXzNx7kBqi7uDI6pZuO62eqg=="
    ],
    [
        "XA3DyODF2zOWnethG2MhwSTeevMea8ID0pbp",
        "PVvuSZple/Q/bxXAHWEzHvrTndrHhcTqpDhZ",
        "oJ12kDfHLxAb3WZWVy7YqcGCmn+HFssa8F7TLRYDh5BRuvQ="
    ],
    [
        "h7kzXze89qb1CLD2Rt+gshzUAIsBqNQM/tdxmg==",
        "deBGggnJ2IbffzmaUpfpp0y/pOX8zCtGRUlN+Q==",
        "j+u9nF1VaDZeqd7qmaSFwVNGkZs/4gJD07r1QHyQfCzEaInD"
    ],
    [
        "xxMNgfStJqJTMIw3bYVZwNnflz76LNSkG8Tny3c=",
        "EeAQgbQ8T6gHsvOfou5iH+LERYq0bv501QgTVPE=",
        "6O6psDh9p2H0+ySSsQq7fSkGpDa6C/AYC2lDn15naQG3r28FWw=="
    ],
    [
        "Jq1QbC1gNUkjptmX//RjXp/oLsbgmwFpy+2hJUbI",
        "6s6/1x7CyHWaVhh9BLpVnlgVe4GbsjXf3aAxVhfn",
        "gRWfaS2lcr58NsTlzuczTFeGDPwiywY4MqyBUXgszjeIXVWjLws="
    ],
    [
        "jPlcEYmLjh4ZvJUzbXD6ZPDud3dyCqI6rzMxgKQp+w==",
        "CBwrxm4Z4yCRPpoQQY05/gWHanTxnBTQEwU3LdwJpA==",
        "efY8EsjlF/ONZiqsPeSPsI4vZDdAmj2YjP4SGIURTe0vg9Mp6cl0"
    ]
];

const testVectors512 = [
    [
        "",
        "",
        "X0V2WI7guJs="
    ],
    [
        "XQ==",
        "Ug==",
        "4YEDbMagseQd"
    ],
    [
        "bqY=",
        "+n0=",
        "+CeEwYfYRPDiZw=="
    ],
    [
        "F/6t",
        "hUVT",
        "m1l+2IL2+SSxshE="
    ],
    [
        "nbriuQ==",
        "IVvTCg==",
        "nVT1goBd4SpOOk3j"
    ],
    [
        "ZxrhTmY=",
        "nq2vygk=",
        "b1r6tYaPDlaAGd3w4w=="
    ],
    [
        "Blbx8pyt",
        "eF4430bv",
        "BlYagH2F3ItlDBtG+PY="
    ],
    [
        "HcG6cgnp2g==",
        "rmPYXFnvjQ==",
        "LHq8ecbtVeBg3gHBmaiX"
    ],
    [
        "Oj+AqLpXZnA=",
        "O3uZpswyG2E=",
        "xxJfa2Xf0QKLjcTyUkEmjg=="
    ],
    [
        "H2MNiaKXpn0R",
        "MZFcWrSNaW2P",
        "GzsWb0QIslcFetqqd9awJqM="
    ],
    [
        "HoEthoSUtvGyUw==",
        "gYeQSQlkVRmxUQ==",
        "hEEA9WtM3xXF/bmDypmhYl2R"
    ],
    [
        "eLmixznKFehKd+c=",
        "8netJjHowVfdrec=",
        "whyIhlBOn2KTRPkZg1B9/+yHVA=="
    ],
    [
        "BuGvi4Pg+joOeF7y",
        "PiFvY/bJbQbw3xTP",
        "uOSmRcxisKezLbv8RCBYgtu54ZU="
    ],
    [
        "UgsOa2cz5jUwATVg8A==",
        "VyWmH5eTI+hw3jlQjg==",
        "ceNjMkOmJgwHM5jD6c2PLME8WSSz"
    ],
    [
        "IBr1kUBXwatJlu9KGjQ=",
        "tpSU98/Bw8g2lvovNFA=",
        "3Lxx+t2yx2jBTMxtmRuhbpEddgm+2w=="
    ],
    [
        "kbhDoR3dB9t3GVkBOJ1h",
        "xx0wSvm5Vlwutdj3/Hun",
        "TpSnXSFmmRl1ioFROhBworEUyjTTT/s="
    ],
    [
        "siopZRK+RJtsIgU/M50TZw==",
        "qOXv4LuowGoQgCixmaTWFQ==",
        "zvl/dOLSc67wfFg4tcC+NmP5FaWWNwXt"
    ],
    [
        "dnPRhfnt7WvHGVzCtC3N2EU=",
        "bp7d9MQz4y4nD/MQ6rYHgp4=",
        "Stsp7is5er9gUcqvIgsunEG/HkCXtNnNGA=="
    ],
    [
        "9CplvTBJ6ZlLQARJLMofMWuO",
        "yKB0tGINMC36FvouHQfpEaor",
        "fLkA86VYVkE8/q9NboGrTTBDTb8moVlyT80="
    ],
    [
        "pAPTQgYXjW1a3W1ZpzZpVUVoAw==",
        "0gLBRc5GI/Js24ygpFBrHw41bw==",
        "K+k5WleU30hmK7js1wvRAoVES//OAHDf/BPd"
    ],
    [
        "5J0SuZMZ3usZCL5H0c5M6CGUSEg=",
        "WRRe+Va8V+QeC7mhkU7qzNw8jO0=",
        "tCoj3EoRbq27Un7/EOrntmmTGG+ZVfaSky2oZQ=="
    ],
    [
        "dmydywwLwicxGiD+anSqi0ceRvMd",
        "McLjwWeRCnFOKXSskFMEsghntn7z",
        "4eUaZFWiPf5iOrqVd9bFAI+0200pwChVpmY5dDI="
    ],
    [
        "bQZ8W1qPM+7GvNad91PQ4cuU/gv6hw==",
        "TuofWXlbKHM5SGWqqPrmArEwLpa/Qg==",
        "CxJgcUv6A3tBPIrqhcVNcrcebRcT2OuiibV9UGQu"
    ],
    [
        "D6kuwmIRX03Pe5mC+zJElEhZO6BybEI=",
        "EZyplS8acPlkzgGqyGfvlnNLJ23ed4E=",
        "6PCZ90xhLZM/utgZrdB7B/mtYbs/v5IPl+bv+VkxBQ=="
    ],
    [
        "7NqhpKPjhVr1buholr1kbvJ9R6uzmjGX",
        "DQJrOs3h8Al13nYd4EJfP1DaF/Cx80yt",
        "pQC7cTqyRN8sEjNWSmtD/N3Uk43Nox+9eNkj967z3Q4="
    ],
    [
        "VjOJxoJ37Ut9SLT6hUN7ePID/lF8EPNf0Q==",
        "uSHtVNZCpdoru64yBdYnRPEAmvWbDndNlw==",
        "MLV7tXXqKk+cjhREQ9VdepnMYYCwDtFvLXGJpuFYJD41"
    ],
    [
        "gf/0lLCdvZvP0Y9xe9C0iPXq+ZMVsM3ABiM=",
        "yrlIs6zMPclrOU/TXvDXx+ruAtiT9/7Hvxo=",
        "IJSda6Jo0saXUt6WHZSiYQ00GK8x4UmPf3ymbCYVvtVS1Q=="
    ],
    [
        "Cp4hJ/zd9YVrBSc7KPWhuzlE97B40X5V8dP0",
        "ekUm+O5mqi6GwnorF11PiT60Jm0HD+s37H39",
        "Dt+KJGNVmDL5o9eKY27WWCfyQ5jsoh7sC1SlFOuFGeMQV0g="
    ],
    [
        "FSvmtcGG2GcJEaUoyNTSBfSusC75Rjx2yUeDnA==",
        "q8r2Q0uaLqVLNctWHqdr/0vPDpwo9Yxpk66N7A==",
        "gl5XbKx72U7JE3jh62xdgPPIRBc4d49DczE3/l0iHjS5JDZs"
    ],
    [
        "GHR9Y+T9dusmr/uI+vR/D4ynCTEjGuSI9ha0Qdc=",
        "3m4OL+XbsLzqOzADadw+IerxngqXrEvLmkgSMzM=",
        "zMYcd/5I+a8WtotiqMs40o2N+kdwcwTslXSwvzHEJ5tpWZ8tsA=="
    ],
    [
        "FLlnD//wSBstbGObqPsI0ry15L/s5ALEBsTjGB3T",
        "zBV7sUI5iUIuAwHtXhmUbVMkvOq+jZCDTcdFpNmv",
        "cpc4IfFQKyWROhkcIivn/up2X6G+ELi26HINdKnW5Rdxksr3oZM="
    ],
    [
        "QjkDJG7Sx7zUBHhRDO5H5kpTFZBwQTzGs+AnF7J9dg==",
        "CDb3VxbFAYkLB3M09VZmktYcyV8ekwPQAXqtv+8p3Q==",
        "JpWCH4GCBdaSDoWT8bAupCitgbhiAL9V9VLmSYdNrxMVEJQZdaBG"
    ]
];

describe("pbkdf2.deriveKey (SHA256)", () => {
    it("should produce correct keys for test vectors", () => {
        testVectors256.forEach((v, i) => {
            const password = decode(v[0]);
            const salt = decode(v[1]);
            const length = decodedLength(v[2]);
            const iterations = 128 - i + 2;
            const dk = deriveKey(SHA256, password, salt, iterations, length);
            expect(encode(dk)).toBe(v[2]);
        });
    });
});

describe("pbkdf2.deriveKey (SHA224)", () => {
    it("should produce correct keys for test vectors", () => {
        testVectors224.forEach((v, i) => {
            const password = decode(v[0]);
            const salt = decode(v[1]);
            const length = decodedLength(v[2]);
            const iterations = 128 - i + 2;
            const dk = deriveKey(SHA224, password, salt, iterations, length);
            expect(encode(dk)).toBe(v[2]);
        });
    });
});

describe("pbkdf2.deriveKey (SHA512)", () => {
    it("should produce correct keys for test vectors", () => {
        testVectors512.forEach((v, i) => {
            const password = decode(v[0]);
            const salt = decode(v[1]);
            const length = decodedLength(v[2]);
            const iterations = 128 - i + 2;
            const dk = deriveKey(SHA512, password, salt, iterations, length);
            expect(encode(dk)).toBe(v[2]);
        });
    });
});
