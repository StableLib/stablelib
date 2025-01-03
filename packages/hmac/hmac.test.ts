// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { HMAC, hmac } from "./hmac.js";
import { SHA256 } from "@stablelib/sha256";
import { SHA224 } from "@stablelib/sha224";
import { encode } from "@stablelib/base64";


// Test input is [ 1, 2, 3, ..., 255 ].
const input = new Uint8Array(256);
for (let i = 0; i < input.length; i++) {
    input[i] = i & 0xff;
}

const key = input.subarray(0, 32);

const vectors256 = [
    "thNnmggU2ex3L5XXeMNfxf8Wl8STcVZTxscSFEKSxa0=",
    "ZiCzHykkuMAVR3RfQYJdMiM2+D67E9cjZ4eJ1VTYo+8=",
    "Z6hup9RHIJ3vKtlhtYmLoMcVL5ZxVQbMSUkEFI6yug4=",
    "Y4bU9J5JY40PbqR9+Vj3qJm+Y7TQhmbWh/Z0DlwCYmE=",
    "1OKzpDawE4kECoqi8FOyLm0uZOI83oT1gNMJzpsm1s8=",
    "jpVD+mk/AkUztsb3JHq3mVSvCGGG4viXlvlVeERuuHo=",
    "83WQlB4g3q+1n8xbSbRAB301536Nyqt9bnYdsfyB754=",
    "rkvl+7doYdRpc/f/vBP6QuaRdu5H+jKZiIox41sKewI=",
    "OT7MWQSpN7TIGRZgroVNU6YlAWC1WetbBiQt6OXMML8=",
    "TGWR0lIcKpjwajCnwCSUuG1tlhzUDY0HaBJ+W4gWFcc=",
    "35ZSasb2Q0QZF2a3MpxAyJRP3rTuuJvfj5JPzKywgWg=",
    "bSIIMR02wK8LubeRJjy0rYXlzDtkTeRi6U6QeY1Rfn0=",
    "1B984AP8fXcRx9fpMTZAC3FYEm9EFKGGF9Z4XZX3E/w=",
    "j7suYmVvp/ori6uxcOcEC0XcEP7HdI9/0lsAttdT7eo=",
    "cQ12MotZsoft/y3xFM6qkM5IMqpyZXlC1vvPJO739EQ=",
    "JAlgV7tgurmrGU3vJ9LqBoVgFonO6TQ0pu1bU9ejjC0=",
    "nzqiiCazdIXKBQFNcUKz6j/72lo1v9IPL5yPzG0wSFQ=",
    "yhbH7R4MdbbDVoc2NhaZJQzTzcDcMv5T8nXEDHSecEE=",
    "5/2pZznntSprSe/Fm/FOHqpV27Uu1qsMeZayCTsY0rw=",
    "OtsEGhta0eB/AQ3vi7GMT7JkNsfRwKLSx2FvVJOR2Rg=",
    "LHooPRKlUo+1ta7s2z0N+xVu5Ps8zxGo/FLV6a8JXrE=",
    "elIM0x4qe9qcuz3Qd1rq4VlOeyYoY8k0y5LrryZeL0c=",
    "TkaFPfGwimcuFP8UbiVbrkVERPvek/Q8x9bCeoRYEWk=",
    "7gnp5FhAkGDZwG7DhDsg9IzvZI5RsWDRkgOUCwRaSzM=",
    "2z1vVR5lLS1JxTRIqNkRNTV4JTOpm8gt4OYJ0DnEjpo=",
    "WMrCIt5H42RFDscCBxPp6rkcjoZjCR4CyaK/HwAS9lk=",
    "jiSpA/pqIUFHLtMFV47wDSIXkmPD9g0G/UtwocEJSrQ=",
    "20WGzme2y56ngTR1H+4yOR/Vsft8iYuYzfL9WqPcw0k=",
    "LvIQoQecpdAVpwx2x0tMr1AHR6fWMdbRH2CrLHfAKRo=",
    "vth8Ro4kPqY7aQXU/8k2DVsr45FKPxbtwNwl1YYPnw0=",
    "k6Klx6tGjXvH4HCOi57kil/f68dXMBCT3UkdO+5sqjQ=",
    "8y1kFxuyZ0e4qid7Yko3KRRzuZROk9KgEdSHsWXNvDc=",
    "6Emb5PGYDWjxMiKkGN9cvZfVP931kMIQjiLUAAW3BxM=",
    "mg5CepAOTrqsfC+wCYxaqRZiDUmmy2L2J6CrkFCQoes=",
    "d7BYWrK63snpFcXRe5AorxooQQ4iRxzXWQs8hbJz1H4=",
    "AG9k6f9qJoUlRAHDhEROkMNGORcA+UEnDwza+BJESC0=",
    "qhhwmVeJs/vJyEtIPC/a/D+FOqAvq5owYePfqnT6swE=",
    "/ITeO350XqLr64YApDwSLXeF6GcwNqxvUWsH/xgomww=",
    "8VUJI2n1vEa/IJgQ7lEIQ8V018R0FYMCNqbCj33XSUA=",
    "iZ671L/alfaccrlR0VZ5Tg3IVedqEBcYT+8IPMJpDrU=",
    "O5CNvkTvqq1EpD0qSLIqmRNrawL3DrR7CeJ6YEDvz1Y=",
    "zw/pfkhA3Ly7c0Jb4m7m8fk1JL52bufDvikjMCFZRU0=",
    "sh4HmIxfFXUCafbV7Uy9ZvHMzH8uVxgMOuhOqXKbdV4=",
    "3kMlkKctltbxqVzOqt8g3QQaHrgfesxNLRRJGLCwhLk=",
    "KtxRKtqSDfeyPuQIQ/VntSLN/jycdqgLHtufSd1A1xQ=",
    "yLj6LJSK+QivIDdy7TlHYUO/o7QLCVv40ks3UGJz3zA=",
    "wxKU+BRrG6qdvcukbjWkgbn8AoZGu+bKEV/eu46g+is=",
    "UiV2G3AWmzKemvdCRUbBeKURWd4VQv6UR/LIDuIrRhA=",
    "q20kkGwnkieEwUvQ9TMw19I6vedQ5nNXDyM0zs8CLl0=",
    "4AK/GmV1SK3Xi36lvz6tz7tup2dd9hrD1tU3n22SCsk=",
    "UVy6KgBo8TX9DaFjCCRWxjB+kAz5CBSg91zQE6lqX6k=",
    "Guezh/po9ysFS6z/JxI9Helk/1qpclbRl+L1a4hGW1w=",
    "fGMARxTLePpg/SDmsP0s70Tl/j44IfDCuulh+vZKYKg=",
    "DZWGdRLhusgIJyMXMe8Ywby6bikoL/djbdnXw2ytSFo=",
    "2hAun68dznPQx4pozTQq1GJIi7xtC7VuyHK5T5HRP6E=",
    "rnSDPjhD7l8u0dGJx/noDWw3JzZaKEu8rF9d/40vC3I=",
    "EexGdFvvEZnu+Ug+yP9GFRQB/bwL1glQiW38oS9d8qo=",
    "CXOYIQs0P6C0zXjKn+ztrkjX5qF8XtscgLQb867NlgE=",
    "Mm0haIiOX2xSZcxfhg5AfBR5utiYsk9Pr1pSB31DPao=",
    "zSxFZvh6JVuh2SRSCUditNMpQQ2MVuu9/HWXwkHH4ak=",
    "xJ09OecxqxIiGN/BadslpzCY5xp2E52fDBdJfT+SC+k=",
    "QSDrx1O4+sy3QmRY9fdhlbCHCoAOS3vgJdcg/JVZXfU=",
    "isOp28E76MKvFTRyJGOV0RhLu6WUAYBNQ9dSHeaILTo=",
    "jmdLKfIt5jYEHi3AdA9RDRSqgs7mHtLm6swwX8BmwqM=",
    "xKqhAPeF1rEt1vyKD8l9tw53zMCc2VujvBtevWa1BTo=",
    "fknxyWYwp5tOo5qGJTitheuEs2cpYqWBe7AccETUNJw=",
    "2o7FZLhHwOR7VnkS+z0GtOfQmeMsAqY1lTccDaVYN28=",
    "bypDSQsqZnCaOj4g3VWk1sIPXplmcw82jvklBrL+gyE=",
    "Oi8O0oLtAevRO+oitXgKp04ffs42/98jm/D9sVec7Sw=",
    "EiYMiFPwfPfkf1wKcHfWqk7kixc476PlT6MAx7dLtK0=",
    "+9rWNGKb3gHkf534NtejY7T0xEQYieo7CpflYW+niZU=",
    "cLfmILBIUOnQyD9un3VpxjRh4ZXKW29kK1Ngo8kvmJA=",
    "KoZ+6PAae1RULGFXkt9Ny9YyET0Px54fq7c+vUxd7gM=",
    "QPYRVv6Br/KUow5Aq4zsf9SYf7tLB6XjN5c3U4trHzs=",
    "XrxIuOPAGsX+hafHUCfs0mYqTiSbPZyI5EGRSzCKZGo=",
    "RaCGjS8rOLZHwJsJ1/x534DhpcEb6ZNWbObbrRfq2IM=",
    "iuzP0uFzCL1JV/d0XNT2kE3e/CTvLAePUmcVtl7qYUM=",
    "k6bfz//uGdD2LQ2FnYyd0EP3VuRPSZC71CAq0lLpsuE=",
    "LFb1c1fVqNlDtgvQJ7DWnIS8oEL2qd3evuZDGILpaEA=",
    "Z8aZl52zxwjqgw4qxz3EaXqDrmVNTdMrkrWYC24fBIg=",
    "HoerJBsBLWk4orrBXMx5lH2NlThKnvJROgT05ZqeRZU=",
    "OmgxcO92F3hw7ljNOsLfHhX4a2JxrgCnMO1bBjjBAAU=",
    "Dn73xJ+x+XYacy0QjhxMlbgCwmxMvWi8k/dcBE0KSXA=",
    "3pZ7oq3iMycP7sqnO6LP+Hr7HeLEHKskDGwEIF10Zes=",
    "2cFcXEoVRuV06X5VEuWCIAE4ebbAVuoNVzp69qLLDKE=",
    "F4Qtnc8WzxATW2Nv7pZX6zGf0CceHgZ3TaVPwQUIzHM=",
    "3TVWQ8y0zO7uxIfuXCNz5ioX5HTi2YhlxL9Y87acfMc=",
    "TEXIugXBRDXKRWDw0dVLSK+29OONibAreh7rFwjstEo=",
    "qEzWHqJeRvaWWDMCnrH2G5DC1/BlRNeWTW7KQeZW4hk=",
    "4WjIa3CKcZ5TbadseEpcfITwet2cOWPsbx+5EGQTpBQ=",
    "Fs1xQtjxV+sHkh9Nmqo8xbhl29eTx4YHYkw7wG4XvAI=",
    "KkrCiYJlWkVRNPaIFTS5t+VzfCysat/eLva3RYFCdvc=",
    "b0mOT5JfMQ/KlCCtxqtGKeO9PviuZRwygEO7pP1lVso=",
    "GMwXI3h3gPgj4ISn776bK5/yng3rgBFmLAGwgOa3Q7o=",
    "hA55kMZT3NzNwgSt106woaROqMyH52trm1Snf83i9lg=",
    "rELQyot+HpO6UiiB6ZVCnirAco4u9EZAHImJfolIrdk=",
    "zI8qrXn3QVOm4/Cw8sQWc0IR/V4ff+x7EWyoHdEDi1E=",
    "SCgpQAEfFlq8GkHAte2jbUTTLIyCHTntI+az+dH6+NY=",
    "qZ4W8i0EMRjChXtJFKn0eC7ncEroBQMlkPCsr35M4ZM=",
    "NWwAJ7fs+yMWvbIoGSFCUB6pBvUNivThK/nhO4aLiWM=",
    "irbZuxePlcs+sTeVO3NmVuU+KCVmaHBc2D/DjMSKYrA=",
    "fkup5/3ko+dWY8/4zfqnBKBSixakL6/gyEmlyV0daJI=",
    "FQbQVkscmmp+OYVJBRH0wcnSo5aGZ3XZUIO0KRiHXAU=",
    "hBU4cSgTBv9tf6d43d8v8+QoRvqJLdEzv3Ud5a9DIHk=",
    "Uz3NXzSCAdBRqIRcmCFSomYeXsZVxHOYXXH/U8nVvC0=",
    "A2lftb8fHnqnLxNxi87ZNAIsrpkhzufqZKYz6FbTLLw=",
    "0iOyxw3W36lw0rtP6Lzn94rblMqOKjCPmP2PHINAe9k=",
    "by/BmEy8MHhh1A8luJ/mpwr5EqQA3XiF5R7hyuo2X8s=",
    "Nn5B+IdSQI5c3e7bwkZgc4C0tmoKyx/188ZEtCZwLXk=",
    "RION5nn8inrdxkE3WD/KwSXKtriaPf+K9ApONdWINJU=",
    "CdRKr7XOB/K5LI0sWn9RHbG43I6KUiEKvD5S0Rnrbms=",
    "xQP4MI30AdAKkDjBSqIZOffpbhGYgc9gWqPzswErpIg=",
    "BvIT97JRHi5SeVHUGp6ir5K02f/hRvGETfMIxSV/DqI=",
    "WJwDSWGyjZJgrxRfyBLd55i050apvgB+5fzkB79AhcU=",
    "fG3rKRYtl4rVp3TVWt9KswyO7+TGgLTlkizEdND+VlY=",
    "sGR3eEl47q2oqbJFBG5MT75OOOxweDQfAUKRuQQW+X8=",
    "VIiLAwoDgn+AvES3fBAo0yfei+kHFGtK8FE70GQ4jXc=",
    "9lAHlFfoJ4RPYjk8IgGZJNBPgM6Re18dQydLwOAqPl4=",
    "nyEFzETjqxQoNiGBR/wkj2QlV4pZ4enBfvbMEmtkrcI=",
    "cypuVsMT0I+2XuGF1rf48NmKaeDyurQi8qa2krY5VI0=",
    "V4pgqWapMnYLNO2Aw4gsdtyvh+rDRmJF4FKp44RM9F8=",
    "vJq1uF9yRnVU9t/tzOKDAI6kWFJfxKOQ3xZtduZf+GE=",
    "7OZVtLmPbttvdGv13UAiylajyNN8IVss0iXRJBgiNvo=",
    "1pC0zopHJhiz7CBJyIbOczk77WVG+4u0Rughk1P5OGs=",
    "3662FveMqo2+xoJ9cddVIx70ZkJKClQiPpBMEDcBNt0=",
    "W4jLaJSxmlF7x5sSxOg3FIP6m14nTZcOnu9gpSBenPw=",
    "A5QbaPm+0USpLkT2Bo19K2bYfkM8xtEDsv54GkO9zBw=",
    "dJkCpwp4DOg/HmKXUFRe/voux5Lb3P2jkC7ikYUi4GQ=",
    "R+cpH6M63lAys7iR6c4hhDFP7jGBXeGly9KUCDL+u4k=",
    "3NoZftJ3k8Dwz6M426KZ3E+dKHMR5RH24dFm8eQxIB8=",
    "8vZ+CB+Lilsaz8SNTnSLjyRYfP1iEY6kQ3hhX83LM2s=",
    "GUT928Xn0EdYkY7tVA4C9lr2w+eit19mfNQs8L4tGKo=",
    "u/4gYeWH3t9lHcCM3EAZNobzYVom+sLH6nJF/vZtLds=",
    "yKs3IN4t1KJ2cg3iOob7guLkJinxRWA+A154eJzwKsM=",
    "RZ4axSHkWyvbggNVBEtIo5Tp3mJfPtCUa6nsZoOnwi8=",
    "ZeCAmmWBqXBxTvQf2qM3ssS558nMP8gNrXwckXGMqZI=",
    "LR6x6xoHDzqgH7XhgGAQbXNaZzWD6xoAB6ObVoVGN38=",
    "eS7Blc4/INvcQezPayArjpPmke7R0TiEwy1qTVQk0rY=",
    "TVnqPeoLLXE9s/sEhfkEfpnyPkiFB4J8bay3wY3yWhI=",
    "kbU7A42SyhHzqbvWOm3mXMBoHdJpib0oydIwV6Xsqp0=",
    "j4s6ahRmpX/l/xR+FRy/PHwY+ulIuY5kgJPiyuyzCcg=",
    "ZhHsDG+MEKfIONfqRq1tWLLU+qGdJwql4gYYoPls/Sc=",
    "Ywpl+lMlCcAl0t1vZmaVDoGtun8zjw5LsbUYoSi8QMw=",
    "Ee0aF0mEIVOhwociLOAM9mskgurEZAKw0JfFLMpVsoY=",
    "qP6U0F8NBmK0ZiQdgoaFQmephSAmRnjjeVaq3wpAEUA=",
    "VX88CbrPAvGngm4zKLzeW6nK8rxMKcOjkfn95M95Go0=",
    "QKW3KmYxRjabxZ2lTeMugBKCNGVBGXBIfiInG6BVjy0=",
    "heuolGbAu4/kWO4fWICSlCd14gNNAgV+g9RVULFKxB8=",
    "dopYvuG18qk6qsplKIR9uPyXrR4VTZJIg4yNjNi6hwk=",
    "d+3t8vbpC2j7aQVy7fcU3FcVz2qmAvtynj8SFpxseek=",
    "ayeMHWEL5VT11HJ+czflEIdAb4/62+LswBW5zP0veZQ=",
    "7tzsCCIPCtGHvY624v047qU6Tgj90lES2O7P7oMc0yM=",
    "2VM9nFp7rdI1OStFahq3x07CntdD7GQGi6nxbFndMUg=",
    "OZcyWvvmLn9e4Inn4S5LY4Sskp/urHisAj0KQBgHT5k=",
    "PaNDM7bs1is6c5U9frhwZHq4P4MlqASXTu9nmn+5FXA=",
    "gCa800qt5Mm0b135SZ4Kq1nhpCnjkML/r6GK1I8cMsM=",
    "nsexVt0feC/g53iLRTdshDl9uMKCWIxpNOokPRdKAqQ=",
    "1viI2bms2Zpd617BosWL651q2q5J0wggCNkHJkKH8ZY=",
    "vq49/YVLC5mZvEqNiLZXG+2bz5iBT3PcpQiYnCMoHyo=",
    "JOP8npiDXUf413tsL3rSgBVtQYpiz4U0x+fR8yB3oFM=",
    "S3VP5ZwX1LrLMADK9PzYckFBlXPbzmU0KxFfXZFULoQ=",
    "PQ76hn17y3GBAI9VfH7UHlePw6sWVMn4sUSM2Iupmdo=",
    "nekrdqa0JIcRmp1IcXzR3YqBLHQrNN/ijQ1t912VX50=",
    "l5oiEzcDf4q6/aqZR72eYvv/HnIZEeO2mwJ9twGrPmY=",
    "mRSCoVl7uG5c96sac2Dp9pYpZ7a/BQ6KfGUtWfrWFsM=",
    "4AsC2WN8lv/rAatsFRIMrMA5dJxWSfrn6oGwS/+t3w0=",
    "DS6PJnJBB6dKJ4xJ4yQGOxTuj773pumDSKB6qLaENgc=",
    "v7sClcL6nMFhjrLUrUHlnhWtEHq/lmm1z5S6+twzc7U=",
    "EY9oEYeOJAHw2azI9B+Aqfi1MEgo7ZSbZFPNgIFLLnw=",
    "7V7vKirGzOfyrt50RlExhB8wkMZIDZeD4KwuwYOG/XY=",
    "63wtTwiIYH5PRGItN3QoGL+rHBUs2zF8x+rFzfQA2OE=",
    "8bkqiL5QWc1SWQrr51yQIQfRfWUGA8ixYFOJJdoOtdE=",
    "+7LpnCh5xEv0kvleLEUurVO8vSHpLd39v9igJZTSFkE=",
    "VPSRcgi5Krv5b35lNYQ7kvZ4j3IK78bjI5SCNdJ5h2w=",
    "yFEn8P91hHvvUL5gJRG6lUXTw8CvQl+uMfQBBNh3sQw=",
    "yZah41ID3t/BGbKNXYntl1Q+xZ62Sra0iBxS5oxgV+0=",
    "4y+EZE6j7CJ52aZQuvAw74nuShtm9FQDgTEA5LyUMVo=",
    "rqMp098dEibenN35MIjdcXRf4zXrOtYc6mW+MNqD830=",
    "7/4eKnX+aEtWi8YBWWPb6bZRSPpl01YxF4YBRir6oVo=",
    "t8c/5mrdksGDK7eetsZbgZ4o5OMrQHCWQINS31a0Ykw=",
    "PAdG3qjfVpRQGGlWd5tTqRskR8cnJnRaNF/i1EJtWW4=",
    "L7N3Chv158zEsb7ZEgu9Ga8sHfIJuPi5fIHMeZxPooM=",
    "q/XcyrTFIIlLbbCNkVpBmNaIeNceGVStyHTL15EvCSE=",
    "I+78lXFp4WfC2L2xQxPB0QAeCV9kgmLb6TDPZxJmd5w=",
    "fm0umCy+x3t2ida4lR0OTYYoqq0HcFJHKhQ5CclS7Mo=",
    "ONKPwheO2s4FqeI3N6wJ6SrTTELhAfAj8C+t01r8QnY=",
    "241cl5EfHgTi0ugb784d2duMlkoDupJOYgSsJkILZwE=",
    "4oFTiaO8YthpOhVpcvsEBqH9UeqEcBlfBCFr79/YF3s=",
    "3A2kjkntCwZGiCFnN4hahBE6/Ky2vKC/nYSnDpAo17I=",
    "THPBAl/4d9qX6OQnQJgwKYRULMNppaxVJhvWo4kQKBc=",
    "lVS01HdYbo03VEESsLKUPNSRreVhFP5uwY/t9Tw+7pw=",
    "59rAwh8Pd9EU6HoVapDa38DQU62w3Mg6DGIf9SG3M7k=",
    "1f0JRSqTLZT5C7NqdAFKNu+LnqScY4pcaraHPShAEhM=",
    "TRyKGok5//v3kmXN0wu1EuWB+p5F+X8uR3Jd2/ZSkLg=",
    "fty4KHF7T5nd7EKh5jgA4XjxyTs2v+wtkDobfKbfus4=",
    "zizmxMDx250QXArAJ2vB84o8pwAEDC6OfKfSkZ1TP1g=",
    "uC7CF+8p3iEazJ1JcFd06LyH3xdgpul+Ow34C8eTxaU=",
    "1GPQUyulRYFtjCQZITJfLLECkWrft3dMaNPhjm/PyxQ=",
    "hA5Pm38X27V6UjWUZuXtGecgrObg5lUbImD61LhrLxw=",
    "we6egi3DWE3dF3cKuFKew89//k4xcnytC7i5WlsqT+M=",
    "W2AEvo/foGfDPbfyMsWP3Yjju3qpAZhD7VlL3C/AQdo=",
    "D2vZjB1U8z2sSL5DeK5cBMfmS59BlXrt7hU40pTdHWI=",
    "x2QHoGWphJ2tLxwrzABCMErlQWn2pmQcyGlh6UhBWfw=",
    "UzoCgoEnozVlzMbOWH/F78fxPOBSQe0EtRhjfbYIlp8=",
    "dwuGlKyer6/yfiwnluxBbr/2jtYNMDAuvUz7OPyWCKo=",
    "BmfXC3hl/1q6Qi7xgPub/XiEeau2YRGw6hIxPK2D6ts=",
    "8a+aH1E6QLI8uRWToMnRNgtslJTrBi7PVnaMxDaLLrc=",
    "SyV3iDgSDqPucAUG1MmMpqUMgieCYd3sntZXD9dICw0=",
    "NrXqeMoBmwQSs2rGJfTdZ6Idl1Zm8i1XISpwei01vDk=",
    "ih1mrVrl9D5H9GQBHFNJeR8qnB4i5bBo44XhJcJR0zQ=",
    "ro/ohd3jimBfeVSklIzyHYL/du9uROkAKkQMkalPKfs=",
    "HB471eFwL8zHz7H8SIp4UBO/dJXfK4K92I0qNIrgHiQ=",
    "2MiJwS8jS05FiW8BSnAkPGTVhKGeO9MsgRE9fVb+uXM=",
    "gVXxZfQMBguvoDZy1We/OVybE8XvbJSJs6xIQBQ6BQ0=",
    "T2S5gp6ebKnTPo0CmCmEkw6/rShjZXqm7nzrECnQch8=",
    "OkEROl3ZLxanSICpa3VRyAaqdnGa8WPDLP8zeB0v2WM=",
    "DAvnlCXsnYTlJsxEOqYy5UQMCPWh5kDQOiQtUEJ7ioc=",
    "hlcai1S+RM96eQw+cC/1WxZrfSdj+sPax/7QMjl/Wc0=",
    "LRt9+qdrGzE1HmmqmYcszjMrxzagmlBH7DpzwwD3i4A=",
    "z/Nnz7gVm2xvACi0ZZaKA3zVUY9w7uXMv7a8N9/hDmY=",
    "S7pDg761OyD/l2koYH5vvE8x09XCwHP6jCkoj3vWrrQ=",
    "vAahAKsuxBybDunc+RDhQmLUs1KHe24mfVDcjS9zPIM=",
    "w+vh28nYKzQeXLuFsZKvBnTCVKEi5NrrmY6CAjO/dE0=",
    "0Rg0fNFNMEgvThx25p5dmgXi2r2V3sNHmGPOQmHyPCY=",
    "1L4udWE0Hxv+LXA4K4ZmeCfQQb9/fAeKB8gOFdOzKmY=",
    "XKE0RBW6MgDASYagqGXyBFxnbypERy8yj+0ZKuzLI6c=",
    "MbYuK61Wy3tPxYgzZrNcAYv5YauULPQFl6j7LfrvsMw=",
    "LoKsebSCd/uorzndXy2/8yeYJ+01ZtFAFgiZG7iHsBY=",
    "LlGExQ8YOOwCyIUFDJZuQxsHQPtDttZCDwUdsaYz25U=",
    "cK5To2gT/4jqNJtVXw+zw+USFBxIji2zgWkEH1SAkCI=",
    "ANGpWiIBeeL0QFztTVWUVVcZ4AAlRVjN9YwLAeBPLMM=",
    "i4Z+L6CW+C3TdpYLOX4sMUnA12Qeja7QNTC80JMfZJ8=",
    "hV+mKuxjlpDs5yn+bH/nEqbnlZM9VGSsUOkfaooJvpk=",
    "YOIZvtHUC40ImSe6m1YWO1o8ed3u9N3BVQs3i7ksRb8=",
    "QVUu8D61YMJQdqSgveNRkz1Mvu4nEhK9JqFemfSMIvA=",
    "hbAEO70qGKGhHrM8LzakFaPde/SeS2dkhWXP2gpHCf8=",
    "lLZ/4jlYARIis1a3JXqATAIQDV2vvdp4+LzTIY6/1uU=",
    "xdNPLv8ZS99Td1fnVnxyHXMVU+WYpSMX/aIuSydJjzg=",
    "WZwB2bMyB0N1l7Qz6rztPvQqVsYx12dp6XQPh+dtvtg=",
    "hlqwg8ar1cLYGQlveH8ZXguamBN82EfvrU1D/RYqzBs=",
    "9yVTVoy1ZEaj4MutUo37sLSn2YCf8uNskBbi5mT0LZw=",
    "5mdhHQV2z93a+5P0WEojcPOYBHAw1bXrydqtkIShOto=",
    "sRubIRVtfRiRCFryZ7T+GUBzVUXbwGuXVDl1Mh9Rweo=",
    "Tnh9X6UbkbD/0WoAaByBYVGD5IXM6wibOt7bPPXcGIY=",
    "nzqRGwA0KsdBd1+JODsysFG7LFsDOFLrzTpqFCoBddY=",
    "OenctXd9fUbSn7Divn3tZUAfaZfO7tZT1iS11Fhw8tQ=",
    "ul0uktORMDw3Ij0H02yiuU3ZynTAVrPE3oO3tnSVZkI=",
    "uTVw3F0bh12Ge1gFLyMo8tvOx+1YCkxAM7pP/rgAxqQ=",
    "PoVRYXjZbj9oDo31Vht+AuCknocWGI+3wRYZNuNSU9Q=",
    "jzVb4s/4FnhYlHzUOMqTWhMQXIY+jM5aDUdxCpMoO5o=",
    "SOAWq3CMEssy5O5wgZVhIo8MS15UwKsQuHijkXvK5y0=",
    "W2Br0wOcwNw9v+oLUnHa06WFQVKN5rz65LcH8dkUL2A=",
    "ahLgBBbvDYMbABcPomI9d2izmBEpFU9aJWeP9wYZ6Bc=",
    "KVbRAX4i7NityUl8jSDTgLhMos8rlR8ujTtUXGOZxyM=",
    "0snt0RAHex0AtgGx9aytvc4ecSsVtaE3CCozCPGbJKM=",
    "cjY4BfXgueO00uUheG3U55tnwnarr5zMHO9MMDyqR0M=",
];

describe("HMAC-SHA256", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new HMAC(SHA256, input.subarray(0, i));
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors256[i]);
        }
    });

    it("should correctly update multiple times", () => {
        const h1 = new HMAC(SHA256, key);
        h1.update(input.subarray(0, 1));
        h1.update(input.subarray(1, 120));
        h1.update(input.subarray(120, 256));
        const h2 = new HMAC(SHA256, key);
        h2.update(input.subarray(0, 256));
        expect(encode(h1.digest())).toBe(encode(h2.digest()));
    });

    it("should return the same digest after finalizing", () => {
        let h = new HMAC(SHA256, key);
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new HMAC(SHA256, key);
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new HMAC(SHA256, key);
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 32-byte digest", () => {
        let h = new HMAC(SHA256, key);
        h.update(input);
        expect(h.digest().length).toBe(32);
    });

});


const vectors224 = [
    "XOFPcolGYiE+J0jSprojS3QmORDO3eL1qScVJA==",
    "NZkPK2Qo4s80VL6idxNUmS9Ee1G0ZSgeKG7/rg==",
    "cdq3CwrDMqhHUHNc8qoQJaMnSm3LlJoDkmrZ6w==",
    "B8mHz0PgILaW0ZWbqIlz+4YQN186SYA8dqEZpQ==",
    "0TcURtgain35bUizWU7yHfYNHwNZ61dyomFoqw==",
    "yz1Tck1uq3Tny6pMIHDOcIxIpFLPBsv4vKRfQw==",
    "ExlEPjKILBSKpiS3F5fluQjrvuGvFIiJQEWFmA==",
    "6xLv9L7CRkihJ5Duwe13kEnAcPLT8pcmaoAh9Q==",
    "9GDi8lx15ADCi8MGfWfeWVMKsXHN7WMBur+tqw==",
    "yip7mu2nCYXoT/3PUF6IHpwzJAQdnoUXPOfYeg==",
    "tvF1BdNc7UeXRt4Soqfb5V2Q+DDaWFoRWmp4CQ==",
    "0D2MZ7h1NuKkjATs9Y/+IjPlt9seJcwfTWZJXA==",
    "ioZuqZewrWJNp8TsX6wWkBtX93VfN5hgXClO7g==",
    "IjjKGAcLTlAzaVBx7JeAChijlGa8euBxLldkEQ==",
    "1t1othO4BfOMtFwJM3CAqqrGC4b/Bh8lN02FYQ==",
    "pK7yKknVnC1zJrL47KpWO4EOfvdPefIjoQ7eHw==",
    "Nug/jATsyHj/SV1m0Q4ICgFpsg9voarnGsFjKA==",
    "rOF38aKoisK5477yPX2Li9t/Iqd1frbW9kEuNw==",
    "djaA5H4FoQ5O3pdnXzeVlWUA8Ezv2iIXbGIK1Q==",
    "0uk1qhqdpJxYiyciDtOvOW0KyhAX15z1Vzp3kg==",
    "jOP2+DVBg1SmwZ8bzlEoqnt9mUz8d6PnDXwhsQ==",
    "msBvjHwHxfdj+AYkTdPzew9UhfhG7Txyz5G9Vg==",
    "AUXcdl1G4sX0Y2jzlmGZ8AAlntFrXCVFlLFs+w==",
    "6BADg1Zw4fHjFjV0BbAgvq2vqdaISdx61wyXDg==",
    "weZkCNj+AU1MpBIqjodP90rv0qCgVwEINySyVQ==",
    "R+Tnhrt3J9bXen8eCSxdfwmw+113zRP/uG7KlQ==",
    "EonU0vhrSZubpp1yRsJPoEhtuIkj6C7+tXxy9w==",
    "/XqEIISGwy8NEcGQm3TJlkudZWmS/SGoJwzGWw==",
    "+WU2LaOCLBmDZ4ucsLesIt5nmNxGMUAVapClAw==",
    "oJpwdjp7YTlNNTuHBsfsC36sf5FKZ18nrjcMDg==",
    "EKumFc/zJs8E5T7RGLuAdv/IqA5Q0TPAERHf3g==",
    "r+sUdYUfG2VOz+Qc3EOlf5tjo5nsRIMuWj3eZg==",
    "DeL9pQcwyY9rl9+clNbYIQ7aOwD4ykbeGiGqxw==",
    "sk32TGqUPx71i0/sqcMO+NQrx6ScquqIyE8EZQ==",
    "gt6TiJgUO/gGTiAiEQrqVGo+YwHr/5FcxIjniA==",
    "Iz38opvB+iTs0Lppuy1UGrIAPowt1AMwkSsLdg==",
    "prVfbbCMQs8iJ1K7rHJ5qN+EbGAmEzpFGgTWQA==",
    "AlBm85x96n43GImSfIbjSCzyaPJ4nktQfN2jog==",
    "3F2CriNCVe0/NSKttsmES7fokRQtgATaIyvJRA==",
    "jOFIJpZndeWb9qtOT2aWhQZHlKyYIsS0P8dcoA==",
    "xmpQmalzBlHbsiYM+t/SDXf9eGe/YD7MMjyP3g==",
    "VNSS6+goesAtbSX8gxK52AUWp9TZr3tYk4FXHg==",
    "+cKeU+cPgZ+VQmvTncUio6TIDLgGwUHE+ylODA==",
    "vELsDcDvvgZkIG1MZYfNeKmjKgEkJk8VqPI0mw==",
    "TBsCE1p+S141k4ETyxFt9VAvu1u8XUd2opuxww==",
    "a+e2GNZRj4XVx6DSAegWW6BXE2groxkhRri2qA==",
    "+qJcZwDLUq/IuJbxKD39cXktsfExw3VlOMxNng==",
    "i/H/b9TCkISNWSZ8ZqR2qx+jKE4qTWaRmM+CZA==",
    "r1O/aF4WfQ4XDYiJR0GUD417oAeP1r5ILDhr+w==",
    "WmoSwy88FqWLgmW4wORNmru7HIMVOuIT7kS3mg==",
    "9IEPbkTH1IElXRMbj/XeRqckVbFW4sw23llD2w==",
    "e6W+jaBbsFjaaC68mRaTIrLljrJEbnpYto98Mw==",
    "iZhaztznQpBj3FPm9Hga19U8GgjlwgJ6uvRjXw==",
    "dwbqlkebmBE7RMZIo9wpu30IEJH/BlD/ec9bTw==",
    "vmVxznNInoVf6bbD7eetYaNvrwGv6ybieS1Sqw==",
    "Vz2hz6hh0Lqmc/qywmaDPPDzM6lt1zH/Gh3b7Q==",
    "vs02xT4L66wDd01Xlp3+ZyAMrr+3Jy2BhSkT0A==",
    "wyUicqIqQb0QA17LPev5mvt7X02DxFx/iah7SA==",
    "iLWROI81tFJeqoUtYRNNaDn1LgkB8YjtFsfuhQ==",
    "xVnKpkT2KaES57cRp710FwtGO/Pj8hqNr1C+1A==",
    "wZPNpekZlqlzeZnxXVapoirgcnvCehG0cI8Ufw==",
    "p/xXoMbce9Boo9oNzAbUT722PuYzX/CRTGQ9Ow==",
    "KzGCbmXneoqrPBYZgqDqGaopPCqbL4XDvNRuRw==",
    "BR3rhKpeX0aqpOfmjT4pPQa/mdY9gV/twXBSHQ==",
    "/pF5gyiuc6jqURPldsajc4AbrUPZRuOqHq9RAw==",
    "UUlbMw5ch+jUE7+F8E1BspPz3vS1yXd40yzk/Q==",
    "Y3tUCfw3GBNKHgeslcCpD7p5QY06r5LRWMu+7w==",
    "dgdsjubMXvuSMlJE/xD+Og0xgj933p9YQYDqcg==",
    "Uy3rJs6GAHqf/+8H63VktzFmhkr0wbS6m7PBUg==",
    "wO8Sc8WhVH9jOxumI7pZ7ykNHMj4F1IjFmeOYg==",
    "/x/QjUmAgxExo/I98pj9fZHMKJKR0LOxlqoQGA==",
    "LdNduosjfGND468SZhePEE5yr80YuBK5ybr0sA==",
    "juqLlbCtnGcUQNdZ4SkmY6wAqcngfIHrToOQTg==",
    "XffhU9X+jEzN5H2yEKmA9xabWsWbGHwOr01yvA==",
    "SIfEcsB+JxYFMg6VTL5tbZay4VpKM6m1wk3Pxg==",
    "nw/TWw0AtlA408+Oag3Ua3ExYrN4VrIHvREYuQ==",
    "vJcOkLLq/hGyoLZSQDoidMtJWyTb5CaqbAnAGA==",
    "38hsxqwsojRCiD2JnqRuiZtWR9xp8AYy7kMwcA==",
    "fXATIs4mtJq0vtGenWgNOn4fRN29/cNwro68Eg==",
    "vkpIkYYBZ4wNCJm745a5Rf8nG2RH0lCH+ax7eg==",
    "XzalEz2PYmTOmSYyCI1o0rhmcjMjup+7AC/2vw==",
    "AdpLGHAxd2YTByhORnx44fk4W9Rlth9eta7/vQ==",
    "KkdpKKO85RMl46HQ7yjXng48PQpuxDwrnMnzyw==",
    "cEDZ9MwtSKPWH6JvrJBRWOPVvjuXf27+Q7Umrw==",
    "wXV4F6ndPHGk89SwYr1ogxMO5o6sqlmgWLh7mA==",
    "BltWKfSyfAZ3jmLw2DTjmL29vdulquSsHUIgPw==",
    "52HwY8nWFr+4ct+jLB8PSOcvdIiO3Ck5hrSZkw==",
    "AyABDonjTjNhoHlPJp/RWS5CFOUG5QCXVan6Zg==",
    "iS1JEwW0lgrRKK48SVSovTbYUoU9OX+M6EI+6Q==",
    "I+sSLBoRRvLM+jWoKr6GSZGEZJEbUKXb/r5mFA==",
    "vhgqLeA5Y8lAus/ika8Qj189Etq1GY9YQ8qC0w==",
    "ehEaJ4BsAv6ztHMzasEy/wz7iTgNxOrlIEIKXg==",
    "HRmUdd/2MO1FDf+arQ2sGLudROje8sUHs71GBg==",
    "jQ/LDNsVyPrhmc6bKOgFMlFGY4cNSa9QEw3mIg==",
    "mNAY8ERlvaW22+cyEvf8TBgZsqE4D8YdaRbZ/w==",
    "ULHtN/bXhoDV6A2eaAbFbkvwjxOw2iWAeU/vbA==",
    "LaDOvAhtLzefe2J2n7rTqu1U+gcdPCJ0+C1UVA==",
    "iZLzqcJUihmt6UTGuXTV0a2iPkBDMmrLy2JaEQ==",
    "9tr33xEaHZMZAzrRM422sJH62UTjLPmXF+M07Q==",
    "uNGPAOQvRVwzRLZcVR+6YkLTQY5OuPfHEweo7w==",
    "hHHhBspAhB7s1gOtdEWROSsfAJDiH84KxBfDpQ==",
    "H9Fn/yYkO+BiAmPgqryh+WgpQLRmbPmvNXotDQ==",
    "fdJEXezobKwgqRbIruvEfMXcQEwNT0S40knW8w==",
    "QnZ6G6bGIQ7+ksuQt/Xlq7YzFzXH9hx9899MQQ==",
    "dyOLrx3ZgnoOjd4t/3WAhfAZHd6a+ejkSR+29w==",
    "nbGgFBbpkpxMzBqFmH78FFTrxQB1CLLbKjIx2A==",
    "OVsnYSE3Hcs227bFJH/3pe+jmm+f1Z7CdxS+gQ==",
    "6zpZPlHB7asUUhwDxVEc/B39XLRi264F6g6geg==",
    "Jv4K2aupoBf1rn37b5HnhGdRyBBDPkNI1apfnw==",
    "i66pk4qJbVUbM1IPV896vNrqHFsJS/vpmIZhTw==",
    "l47EK7L+GQLJS8Q2Ig2FYWqioUwAzlFdHwSh+g==",
    "bxyEblQ8BoUeeogq+4BQv5l+31PSBjXshDZmZg==",
    "KlVR2izm40B+Jf75VtzLs+0rnut58yYUttQ3dg==",
    "SDSILVVfgNBnP/qKvjMDju4ifc9ve5iMk7HErQ==",
    "MGCbqzMhlct5XcH4/0WbOkkhBQJPr7kqiMqxiw==",
    "86vsKSNtqvXskxIbQnt+M4o2WsP/mrzzm//7jg==",
    "3RYqomX4O/9F+EKsi6uPUynmE3HS06pITADVug==",
    "Y4XeTgStSOprG1BqSJTHeqFIRotkDILFbm7veA==",
    "COLX4h2yVQxwrTvjrRhFn09N8Px4dDnSivWWrA==",
    "1pdO7o9RLU+gWSO+YkaNSLGRYQIqtshvt1bfcQ==",
    "EAq6M7aghWbm3ZhlwjheEo2BV2L93ume0Ybamw==",
    "M2eqIXVXOeCbnckd/OGHzCWR4mo4GyohX4pwdw==",
    "/HXa9rWdOjiLCgQhuzpPYqurNhupeNMsvHYaxg==",
    "PaZOohOH5vcX35aAwxmdU03R6qiWiAlqB0b2og==",
    "4n1KMPpJIrLnKPcohgrwyVrYZQaxp/F/oEM7ZQ==",
    "WzIlN9Cm76QaTeIeA9VaaQ33KwVL1k0mMg+5/A==",
    "W9fgcUkbavxOWkNOkF2xICMAj67sEd9C96kvbQ==",
    "AH7EUjSY/5w82kr/WY+cn6d3BmYaa9ncIYiI5g==",
    "CZeumVBzdB8Ff1c83Z9v4giAx7vxPdC6kJCKCg==",
    "B/s81kUuBDgUNMOFG4i1lGDbpOInAYVjiT8Aeg==",
    "08Chd0SKYBd3Fk2DbB+XTFiaT+nTLYK9wNzbjA==",
    "waFtWwLFfTtoWXUtSQHHc2p7K2o3QXkg7guscg==",
    "2ZyUgV4M2zxbeNC5o0Xe7wXCxZJ2+3+FzbUH8g==",
    "sFLTS/ZxXTxHZEfm6JYPY3s+uO/gvb4mBMCZrQ==",
    "wCTTsJolIY/G5MSgGFWRoK2kVhQQFwzRpCHl5Q==",
    "qzaXM70XOqD7lMwL+Yl7sRq+chr7E5CfGGp4lA==",
    "YqTvr06KCjolejUTLE4pxe6RPpBwwwTFHhnPyg==",
    "OknSlgVt09hleFjcXongJVf5y+S6fzMXItkQDg==",
    "Hy4kqvmA7068GgXt3B1hCOMjJbFcNKljPKb4jA==",
    "WppE5lUv1TdFmhymeepLibyD7Fm2Izo/CJd2qA==",
    "7GwP/hpg/U1YA84qPqIx0jvJXexsVjEY7LjZyg==",
    "OIxSwGs6gv2mUNw8UG9kOas9wfz5kuzZnyWDzA==",
    "vd+g0boJrOBy0LScw4oYXNc8Tm5xhFiymJ4uFw==",
    "9TblJjI82UI4njCSJKWl3xLwv7EI1wCjThGiWg==",
    "rVVRx2Luf2vVDi0RJjdkQ0LGBTfEPXutaLTBXQ==",
    "yXYueor/HSbVRfrFBPDc+duMR2r5RHAcfHl0Fw==",
    "2x70MCbiiXshOGHrKCMD1bjue4cIQGU7nKPEVQ==",
    "VFTtdovVcGthM/l5Y7OxN29tDk73H/F5jKw42w==",
    "OzzmgGLn6HnSIhVVBymL/20B2bqE6W0AsA1foQ==",
    "vBLO6XETMbMG/j9SxnD6UMAwQ25uWQ0w3kv54g==",
    "7MGIrmoKJrB2A6JiEmLXgnHyYEGS8JiI71FVRQ==",
    "MZGhHFcTlKMY+PvFEH+wOfU0nl2D3bQf5ES/UQ==",
    "a9DluGlpaE57Pm2VObWIrk1m+HKRmVCUzn06UA==",
    "auHv2W9DVoFRfQHmxPvVi4iTsF6wF0bVqz+ZIA==",
    "8uxwOUGgILfhsamyxnoB3hME/MaBbPpINJtIuA==",
    "TC8DaeZ19svUZfcdZcsZnPPJyFJCOP2UnpYH1Q==",
    "wqYk0ra6zIuM5SBA0wIX14cHXTeDOvLa0kVfvQ==",
    "4mP7t45MboMix9FaC4jjUoey3Lkavu4Z3v6Ghw==",
    "Ztq2ZrNsez7aNMUP41cO31+8Vt1Z+GjMFruIlg==",
    "kzc9N4UZILi8rTw1PmM5O2l5ye0Zu8loFj+p4Q==",
    "IiRQ1WnDhB+mZu8xm5hGjeOz5oXpNRNQRiwBug==",
    "+hyvMHWqCVl/gd1fOY5aO/yZvgRfbMMukAIB9g==",
    "6ggBfVzJm1h4r+cLcY9EzCf5jsmshUy7e4GEmg==",
    "v2YMBzOtKCsxwVQtjJ5gz8N6i6GZMhAdxDYkGg==",
    "9Elp3bjBzXgMbNhngXTbClYKrG2mME/1vSrtdw==",
    "+YV8wuP0dzEi/FgEh3zk20j7TvApzn/HZfXP+Q==",
    "pmZas4TvZZsR612wGoF0myJp/suHhDgqOvo+7g==",
    "hdrIxCHSDj/1thGkCbTztKTOvmZiseHd+cw+Gw==",
    "bpjPG9VwZ6CWAObHs0AiqddKbCAGakwTBkYyeQ==",
    "zDukDRhDmAjayKTNCs5EtVxgxsy8cR7pLmZl6Q==",
    "SJ9BEB9J06hSdS0l50dxK+MfC0AMTm54j3BMig==",
    "+/hZAUnkzDjpKhw3c1mdjJtOr2p7tJ/W+oJSbQ==",
    "hQB9XeDtXsplCbNva+AkNzcTRovc+Maw8tC3eA==",
    "ESb5pvWlZAxSy7GyugOFQxoOdXJM9B3QvHQ45w==",
    "J2RJyfjtRiUUBSq3MjRbPRHMlRyC1ZlLiZQmxw==",
    "Bqg5O+xby//4eZC7VdJDfckNuXR0mKzCWZ6weA==",
    "c/BH/z+/S24O788crPvwHhh3G7tSgNvAdRRlEQ==",
    "/91E1WAWAI03WOGJcJDjyfJ7YYz8Mkp9O2VyeA==",
    "SWSKYJmoyspybNlxHb0uc+Rgy78Aupgv+j6L2A==",
    "mEdyt9BHSrX1kcu7VDI+qRznB+JVGD9mxOjSog==",
    "wx76KN/A+e4pbwCqWHUpHt2snhXWGY5HVpfLjw==",
    "bqT4qAO/J0ei3Rzt9+mZ4kZIiO/6Qc1cSNssAA==",
    "DfatmPBKeVwsaeoGxJyiel1x3N/E/FX5xAdYUw==",
    "BMytLvQzWf6VI7DUCY60gFBoBYBQRznYUIj+LA==",
    "cqJDSnWgbes/YB9Heqth8S6DqsQxuzsVkuJpJA==",
    "KYCwj0JqvKEalKUP1Gj8m5wHxv9o8Ky+mkxxaQ==",
    "/VRAU4aFMDmvqTcoq3CS1Yl2Wd1ji2CnunBlrQ==",
    "CytoqCSH8K3aKpJQVWyxtY5eB+huMsiJEFRr4g==",
    "VFBjd1mqpiRobJLb1mhrUBgFFyeg47IZpqIbbA==",
    "ydqjKFedb43MV9RhQLGcSsC+ZrQzetoaSx010w==",
    "vQ9im8WEStD4euBqLSWpbuVakTcmGPnbUe2G6Q==",
    "7uI9FzzrvUITcQygmnniqanj9IY972c8c4M7/g==",
    "R+lRwHl7xqlPnrwdbJ96mNGjMnCRIkZG9IoGmw==",
    "1xBxYsh2o/HjrffEd91+btUKfKNz1CSvXmjiYQ==",
    "pt4MYmv9lX3aJMsdkkfcC5jDYowfsi2+0M7HZQ==",
    "WkCPKbJiWUx+rTiaiC8eJ8Pqlnh3RYIHvlqLUQ==",
    "l55IPL1Umm2T9hnmohVgvFWC5lRFQPNPBcdTlA==",
    "sm8ZpmX77vcD/sBWGwOqwkpo2cERfYVoRGGkUQ==",
    "XjEp8x7+16DyAH11E/jOCDXFfH8zk+D76Adl2g==",
    "OT9rxYsvLJ2tci68FeN6uPYtIeJlco1OX+a2Hg==",
    "5qtr0Qle1Ln0JR/zuAbANr4qaJBtzGG9kjql0g==",
    "+MawPR6ENnNKYeDMdn8Iu0nwE1YQxKgnKyknIQ==",
    "1StwJA0JhjZOkrP4yIP1Jb1fMgpZb1GwZdQs5w==",
    "S/UyzDf1VKy57LWYAPxEtBUeOp8hwjA9aXAxQA==",
    "L86FxDWHkoH9aUT/E5socJysFobHFmgLUeb0fw==",
    "SnLbjKpc9nvo5BMSLAATxdol9T6YwkwMMNiy7Q==",
    "m/0BjA/idfs2Ztk4W91hhNc2l6XazusX9fillw==",
    "ysqH66P2Eg/wGtS87e6JkxFYwTRfZePXcvOg8A==",
    "DFa2uLotYzy/DmDmMeQMDFcjYY9HiBGiGtxiIA==",
    "Od1aV7EMpSCgZO2MraCA+NSLAhYnOM8ekJvsFQ==",
    "E4NB7zNnSkHoiG/QthVdV+UIIJycHD3Zv9oT0Q==",
    "O8zZypXjvFkhv016z8vvsXQrnooiBBMdaqDlew==",
    "r7vD0lXyrD+XeT159J1Q3eYzGeetquVSjnGyAA==",
    "rCp8CbEYwKPppYGCF0Tc7AgjXZlULTwHl/fmLQ==",
    "2BrYILrcCqdvDUacguk1GM5BSseMO8v49Iiypw==",
    "0CrmtO9RTVWFu8fkawmQGouPlOH0Fnr/YuYUig==",
    "QADu5Sqj4Tk1BKpVr051Z3YBbH8ehod2O5c+SQ==",
    "qDSYGGuZY1SEpsqsX2OsgNtbzflWqdpFu3p4pQ==",
    "ZSOgm2kVIpvonry6uaZjZLCSdwIiGviC2xRh7w==",
    "R+6+SSNuKInkP2an0t6yNGXkUSm4apvXo031+Q==",
    "eOFFxoG4eBJQqSd9JdKlEkQe5yKI4YCAAaITHg==",
    "Rvhb3Fj9X0fus0lVbg0xRnO1fkViZQtoIWCmJA==",
    "AqfRn6QRgEryekXByhsB2XPtOSlKy7mqTQbJkQ==",
    "EDO7c1UPzySZWjkpjIFlOswDNsDEpldGgywCkg==",
    "/4VnOeVfss6VAWSK0jGMMTHAWmS2ny0X3vHaSg==",
    "qbjyDp5sQhWe2r7Pusky4yytOkjqOxFNK6TzUg==",
    "SDN8mmBnY+j2asZoKL1f+a82KivbptZ9P5sVnw==",
    "Rex8lvJ1WSQnbxgWM3exqH6I+2o41kZidOMNqA==",
    "TWiENOtDuvhCS4u4L0/7s7IBvCPlwC/7y6KvrA==",
    "pDN9Y5x6bCiSB29fLc3Da6iZbjKiAP58aDkICA==",
    "BHQp/ZQDIYK0dWV/Nao3jbsP/I7yCz/kAUm2xg==",
    "+ZOuDQNcATPddx8lTETn4qgxVNz8wndbt6mH/w==",
    "W2HBWt9cmUOo0TVg4qxR0Wik4jS3cjOIzU1Txg==",
    "TcCIYa6Qz88h10LS0hsat4EbVABsUCv0XDP4pg==",
    "cMMfVMYy2SYGhTegBzH9mmF7utjJnBhFBI0W/A==",
    "hQuifcPQq6bxgAFJuYYPeRzWLANblttnHojj/Q==",
    "y1+0MloAeLrQ7kWW3wP7kdd5O5woiE8SKqLWMQ==",
    "ekOnF09/jdYBN9MrM7LTh2YiKpLrweQafOu3SQ==",
    "Lw5QRtLL9Al1Ol7EUaz0vTrpYzFVzR5UepW2rw==",
    "VXTB7zsjZmEax3bjnu0ao0QqY7CxkwKui74PVA==",
    "8U0k2zVk48RJLPqU+9js1K8AYTy+z8wYucaSDg==",
    "+RFMK8RBfdF2apR06SnR7SqMd5ArGKPHSE5jBQ==",
    "RhuCH8ybeXTFX9ePVac4qz3lNgpFmlUSJ3jZ0w==",
    "V82ego8nRQdkOqNr3SsnssGK3L2amrHGWE6KqA==",
    "2P9rIK2HB/gUxsUCf4Dz0zvNQ2kAI7f38sN0fg==",
    "Zf0KCeoywP1y/YzRpFJbrLndbu2Rv50KYxJq8w==",
    "BB0Iap0dvKtoTiqlnVsEqWabWhqcrAwI56/y3A==",
    "3uhlgy/UWhPhiyW0Ro5MC+TFDbIOKyXjYiCXNg==",
    "0cxQh4NAg9P0HjZ/pW20VadhmZu6QAHDdcF3yA==",
    "lzYfIu1jqtOP101yu9eHn8mEbh1WY0UMRE6EyQ==",
    "slDodP5f7aNLCxLuqwZrkWsVQWeP23yIx9G+jg==",
    "GbRDdYbQBFeGlJiWj7rYArA3Ms1zRztBrI61Jg==",
    "6+9+yPl0vqsulQJiVDibgU8YP/ZZuhN+O2+m7A==",
    "UeJUmTx6ckNrFKCd3AaXOqRM5D3NAhmeq/R9tA==",
    "qan7uELJyAUQfiWzcNYfCYU1KRG2c5sNdLS7JA==",
    "3fjskZLHYuuqS0pVpq5GS4TgH8AOLguAH2t8eQ==",
];

describe("HMAC-SHA224", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new HMAC(SHA224, input.subarray(0, i));
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors224[i]);
        }
    });

    it("should return the same digest after finalizing", () => {
        let h = new HMAC(SHA224, key);
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new HMAC(SHA224, key);
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new HMAC(SHA224, key);
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 32-byte digest", () => {
        let h = new HMAC(SHA224, key);
        h.update(input);
        expect(h.digest().length).toBe(28);
    });

});

describe("hmac", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            const digest = hmac(SHA256, input.subarray(0, i), input.subarray(0, i));
            expect(encode(digest)).toBe(vectors256[i]);
        }
    });
});
