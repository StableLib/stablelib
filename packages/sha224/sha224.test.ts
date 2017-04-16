// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { SHA224, hash } from "./sha224";
import { encode } from "@stablelib/base64";

const vectors = [
    "0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw==",
    "//kpK0IBYXvcTTBT/OAnNBZqaD19hYp/X1mwcw==",
    "AKxg8w6b0ZVvkUyOUSW2ncwxoXlzTmqFs/cCug==",
    "5hUgIYWqvirKkkvsKeWhI4T4M56uTmTJy6nx2g==",
    "1w2gcF6uQqXFltkvMx3aJCG04U+LMDX7c7i3AA==",
    "mAKctFijmhY1WWOSLTLazZQ5+Q6f0QbUKg0SPA==",
    "fZLn8crRgY7R0Tq0HwTrq/4f72u0y+66w0wpvA==",
    "3dW6uxsF2LzNZErcOTqeIwPIUNoxkixNoHV0+Q==",
    "TAcHCALiEFL7ApWsBXHK7fIZFDra4GJ+KFDtqg==",
    "XTyjv+c40z+EEGmt9t15uYc1HOWArKIzJrOn5w==",
    "a1NzxTWk+l1W1sSVNXXOZJaAMbsBm5Cfjy25BA==",
    "dn0M3BEHm6jconbfXEuFUH3mfc5H7aTNkZbTEg==",
    "AsUTl3tiQtL6rAlMrjwkfG4nRfinFJSmBTWi6g==",
    "HzlIIxDiIJwQqIx/1/wf1WfzZ4mAjDfTAEWoKw==",
    "VbqB66ZEGDqyRgwjS7lavaiY6YC6l2WE4pdyMQ==",
    "JSLis1qDVDbIChIuRnbeZGkMgUQNQtvaQO8hUQ==",
    "Up1laovEE/71jaguG/Awjc/gQp3NgGh+aclGMw==",
    "oVP4HGjZ//1N4KuREcL6hujtypspQ3YIMHehNQ==",
    "HscGrrIieyY6EF7b4lYuBSHJZCDaRVgBIydmGw==",
    "SQStrfGdCIkR7g79IKmrUR8nhsj9Q/Hl6L4qxg==",
    "bOJFwpYomjL2YZhv8cgOiTu9NesLGC7cFKs6fQ==",
    "M4McRZpDy/i+tt1QA5dQ8eo2iKfq72jLLwleFg==",
    "60vC6h9xRugnSpbodFhcQBJW+5If/H6TXdx//w==",
    "CaJmyYAZtrKkMY++2+pUga8B8K0q0W8JmRo8Og==",
    "evKBTNYQVHPuUw8rPa6ZKrtsgBQo8zQwUB8Jpg==",
    "xb1hJyQwScTV6eOzkeEr2obcephWkQp1cARIbw==",
    "/KBt3i3NIS5sHBG7IrGLT1WCICZV37m2yZYMVw==",
    "CFGZgSD4zkdILaWy6yG633PJ8UWSHu/TNFnUnw==",
    "7TaiCSU4xdR2mReVPnNVoTBy3a2Kbl4q8d6W9g==",
    "LEqJwFv9CbcGi6/aN7AxTvzgKvrhssJdzjNzJg==",
    "HVUqTQa7iggnv+jaK27latvRfOSBCQjVcgdvbg==",
    "mX0YCRLgZVRFsHJZJ4qq1CRjP1/2vQr+zU8V2g==",
    "cURuqTOBugkflK/Nxbk4MjKQoaAnwip16IoE0A==",
    "93CH1vSuNOiMYll87AYiD0xpTS4OtwSCADWuag==",
    "ZO54sKbBFjgKTBbyRInB6UpXjlWEU1N6mBmi5g==",
    "85wchi/cmrSs+lD+KDy3WVxgj4xSG7eJjPcdNA==",
    "20gqJslIipYzWdFFkUYS40uCHMbNwRETtzveLw==",
    "x8RfOqXu3mZNbM1RD2KNTcPGf5OXP+BbAWPKEw==",
    "fyMOPll4RdufjWG0R0CWj/VfLfKMpTimiSfxMA==",
    "6lI2KpxmtqX/O2Qvz+u/VPeTsIjSnmhA16XPVg==",
    "hLBk75wT8e1UrQuPwMwo+bzlAJUA4c2SyiuuBA==",
    "onAigb1jynRVU8sYaT3XCsmnDNc8AXg3J3B8lw==",
    "iSMfz/xwIt8gsYRihfqs5Er8xndoXaVe4C2U6g==",
    "TFsBxQkH0JfdvwkjuIWia1jf9XYcGu37jVNT9Q==",
    "hODPM6fhwOqkbzfpnOXIspLoGtYTGHltGpqQww==",
    "J+WaC257kSXUyqZYgQrlBUzkCpoKD/5uNkNevA==",
    "x/IeK0yJsqbmTZL5P8QUbrWIZQPBIx7mkktOEw==",
    "ZTyv9Q4HeoVZkpkPDF+Jx1+hjRzBR/aFry6pkw==",
    "anvep+RW1TObfZwkTiRq1lsYupXgUY4gGqp4iQ==",
    "g3refymPgVnm4kCHUbDEgGSMtv1tJsVRmD8xdg==",
    "vu8/asQKne00W+QSQrss+SS0V6RcrMaDebHcSg==",
    "bSkI6ztsiVI0bgtluUBtlJtaNAEj24OxUd9fgQ==",
    "nnWh1rSk0an1qm+KSK/W8/02DS2HI7U9u2Mgjg==",
    "Q247/pSjk1nN9H01OV00wENQGMiLTpbmjCJkWg==",
    "wgnfLpngPWefup4UqvlYrBsKIgdrs7UyoNfwkg==",
    "iZHfunQoTgTcdYHHw+QGj/bLemNzM2FCmDS7Vg==",
    "KyzWN8Fq1ykLsGetfY/QTiBPpDqENmr8cTD07w==",
    "6H9byTjDuYHBl9SxY8Y1pQSfrIHExkZ+ElG+SA==",
    "/Zva9cwoimA9FiNlHVujuIAdFgKwuSIcC0hDXQ==",
    "h/IH2dhw7dfaYXU0c6Ufw4bieSo4YflJvqBc/g==",
    "ye/3n0QSzkkpbAgtx3cRj5LJrEE21OsyYh6ULA==",
    "3bx20l2YGWk/NZfW8JBE+NbMvRLwgRVvEJCvfQ==",
    "ZBGtE6o2VDArrI4r/RznbzfjszlAFLviYAYs/A==",
    "BJ6N1+qzN4zp+CO/tWnlsnAjXUt/liNgaXGZjw==",
    "w3uIo1Itv3rDDRxo6jl6wR1Hc1ca7QHdq3NTHg==",
    "EUtf1mVzapZYXF1YN9NSUK7XPHJSUsv3+LEh9g==",
    "fZuETKrJ7JOuIVntPTNsVTliFtrGrF3F3swRyQ==",
    "4ceZEJ3uoRf2jdGCazi1FOHSZfEai2CyRjD/jg==",
    "ApoNAktsC2PhWG89NBEXJ+N9ScoS5/Ug+pGpJg==",
    "LqlPBKcsdwqY4qSV2IbuZ0t9D7mHt7XCIXqHcw==",
    "+vRFaI/8o07Xg/lIuPdFeFA9SEWDbK9p29XrUQ==",
    "kexZrHyY+d+4aeEcgAJ/ik0xEyRZfm/GE1Ik0w==",
    "GQ38nHvdlU5BXlQ/mbALURDtahIYK//cqnfYuQ==",
    "jDqoBfp1YlR28yZ8IRsd2lLhgQsFjvgE40vuWA==",
    "v9DlF+SjQKTg7xrDBu4sbdEojHdTHvD9Wstz+g==",
    "xiGhjX4Jl2KWy8OXYbAg5+NGBC/HNf3xBhSPPw==",
    "J+5ffj/knq7ArgqT/Zce3wMEpMBRO89DQkyVog==",
    "vZ1C8pPaVyIZ8I1KOAgdID5E9hLu3vk84Nr21A==",
    "N0z7b7EnaHF+/tJoFxjBGyJYjEKducca+161Yg==",
    "HPsQN/w5Q1Wen5Exg9txOSzUvGjN/UfX3snJrQ==",
    "JTfgFdWUXgVBvEgyCuTf9/6rkRInrg1XnaHNBQ==",
    "ASs04aUwtoieh4Y6WWRe5P/rKSozgV0s4RkY6g==",
    "UkLdTf7jieZo2P942pstharhLQwiDo0brbuoRQ==",
    "SBPXDh1rtiMs2SV7UTL9ugXhpKhY4jfDA8+gUg==",
    "BTC7pDrmOTZV8h9+6mf46OgZuiJa7XjKi94HXw==",
    "T36vSp0AALDpV9/kbbME67JmSjKvQULsdL4Y2A==",
    "aM8judxNw0MINbSEZIy/EmlAr2uuUUMaZtfw5g==",
    "oJPSEZxwdiWfGU8QcHcGHGHHktxTJsOk06Y7pg==",
    "9OiD9/0SrNNuOJGYbk1/8D8+FQ8JzU+1igI6BA==",
    "CBaGLFnONeDXiDSiIdO6viGYf9qoHyDtYdnahA==",
    "9BWTNne7NkxYlyLjC5WPK++GcKEPH1CC95/bTw==",
    "5AxWMkkLuNrSKDttvcqHD0tatCccYRJ96Zm98A==",
    "stTmzXr8NaR1Yg6hRGuQJNdniQuFk6tQJ183DQ==",
    "lIYW/Xgo8J6KV/mGWJlICF0Y7DVQ4K2o4BJ2ZQ==",
    "KxFekwMzo1WoLwdO8mHea7KULZ3WT5i6Etkt3g==",
    "buq4ZLWtYYzbGuecex3jECCWagI1Cu9xCI5odg==",
    "Z2rYHyE+A388m6IxD0nd2k1kdsKKjvwARtP1XA==",
    "A6KMkGi8EKb9h6HlPwBBX4zplMlo3Zz/YNawog==",
    "AdkdCE9ADFke3XULZuwkgsg0zg4UCjfm4ULP7A==",
    "vK2Jnnx3F2TLkf9grXm/1in0gDoF/LzCTo8+eQ==",
    "bgghW1Rw3etn5EpJTlLiWanCxPvtSvXcbbPpKg==",
    "5cRb7W+L/Eh/9xkLEIr1xbZvbVXTZbWhuhVpFA==",
    "DbVdg7ONQtIpykLQAbCXWLXz8DIQny+ZnFU2VQ==",
    "rU3xr5c6J0dWihuN7xXjSjUKk/RbqEWWWA0R8A==",
    "1JBYScjE6jIVmkMbUrqsCS+QA3CT4gCgxGYR+Q==",
    "qTbQqgkbgnuthmRMlGAwaKs0pbWeKdHjurEwOQ==",
    "RtIU6fqMh3wnkcyOZxaGhxPLW2d8xNg4JCybGA==",
    "ro0+sieqNVgQHV5aK/bIYsn3KXoxo98k5FAiVw==",
    "RGLDZrEDJtT+9G5xkwvPk3E/fUX6yZY1IP9f6A==",
    "Be/DV4HkE+y8x2OuE9WjfBWc5czubqoc/3ylFg==",
    "zdugnX/ggeejnEAXs+33qRONHLhXVZuprSyTng==",
    "Gu71g8RIqa4A+8kxtQvA2lu4Mj5haxEHbO6LRA==",
    "AeWr9QYZtcIHjnVO3e3PTejTEYWiIZMTy5GoyQ==",
    "t/8RTKd3V8rWeAHmdhryD0y7gyiu8pD3frYSww==",
    "CPQ99FR3MkJKx9A5CtirPUl4gmRiRG0TsrRo1g==",
    "rDeZ7QnjvZ53D9OgBz43H+mj1OPUZMOnAjzHLQ==",
    "eV8WDCdf9rV1Ax1AU7odHDJ0TQnwBbO/EL3R9w==",
    "0u/UrIq6MxUdA5niiTdppti7+6exKDiL+mW4QQ==",
    "+FkQ9k/uK4+R3sgGT3XLl+H/yJWu6RLdOUX4OQ==",
    "di8YwN9lw9DqZBJsim5R20Ql521Nlp7Q+DiZvg==",
    "0CLet4dyp36LkdaPkMofY26P4EeuIZQ0ztGO7w==",
    "qALYthilAzUs28wfvvBOo2SZ6nLQ4y0xTK+D5Q==",
    "beEIjdlclTWEkpSoY1pECEujbk7vgcbWe5jOkA==",
    "aqEVkTAqMO+s+HT0CqAX+FRdPZ6mjUeZZawLPg==",
    "MoikdaSBfS5CgwxwnB3Biku9WdvZA7Q8pwLydQ==",
    "zO7n9u+mCy8s4QkPuSnWBo9+4wHnqEBy/RY/fg==",
    "pFsPz6w/BSebfoJ4rtk+N7Il5qmXZk+Sx1VURw==",
    "VUycP36SuA9BIeAMwUdTXTd+rrT7H6jiXH+BwQ==",
    "Z9iNoz/WMth0JCR5HfrOZy/1nVl/44s/KpmDhg==",
    "qAy5HgimLwYr0X2wDQ4ZedBB7etStJeyBSZrnA==",
    "FuM4ohdM2qDR8cpvWOj5iBuUxIvskfK8EerBFg==",
    "z6eiNxeI3zyfd55KLiEbZIJs4HGZP5EfxQFuyw==",
    "JDDWVBf1ClTVdkFMHLoPMrJcrkFRQPdcM2Oxsw==",
    "NI6wn0zHCbBwlsm5xYoX03VO55zOqWHxHTR2CA==",
    "nplo5CoLEh5FJfaQWFnMrTKzob88yguqxxjYfQ==",
    "kJK88KYihYnPhVGZEmrRvPrpsAMVcBoA4iZTvg==",
    "2WMS6pPBbDOfywIZqCYvoEllKpcS3QdlJh2DAA==",
    "0edimkrgYkJUQXLXyL9Vs86JIRo+/4Quh+xXFw==",
    "wxVbWa5AHoKX/Ycw1s6+s0ziq2s54V/QgA0xsg==",
    "giQA6lJ228t3o0v+DSh67YWxzFsp7YprDZz3Jg==",
    "mqJU8cYH+JbaT1rOuuzjGhSWkVKNUn+QsBsyiw==",
    "SkTTb1JPI3XnY3T/j2dbGd91+2ke/Y49skWxjQ==",
    "EkQPQxyzLh7LSlVUjBVzQYeFgZqcW197dFsEdw==",
    "W3v3LyMUT+U8zASNsuax/ZnmcQeo9UnzhBkWfg==",
    "7Zu06fXF/gcIKcWnPh6n4TMOAWIBSxz+YHBxZA==",
    "xjXKfdUVwtVxez03k94VcOqQKLkjlqNvagROQA==",
    "UPFE1x79o+OGSroqNzPkyfvLExnNoObQSTqc+w==",
    "0GDy0FyaZ28wdAF1HlggmH3xhfK34u5GWuwVhg==",
    "v3G252AEk08DuV7gQ7mnD+v3PDmYY512H8XXLw==",
    "lUbFmQW0CiUm+wGnJce/m0/pTv/3zU6z1oJveg==",
    "ASDEcvX2sy6TVBW6hkI1Z8kL2n21UmREQAuxww==",
    "yQQEzo4ncp521paLhux0wqc8+HJK8Su6btlFDg==",
    "OvOi+1SX1IGdLIdLljtWBAMQfaudwae1F/GIMw==",
    "z/YT861DWjYj3meOm9tdsF6O1bqmFXaTRfY+kQ==",
    "tenAHtVrE+5UmFBJQ1cgQbrWxNmWXkflV7SdtQ==",
    "0tRjc4KtD+blh37FLphZtOpbwdexMoOII2vFQg==",
    "B2aagyI5UjtgvMNt6frlvegdP7JiKQcRHyyeig==",
    "eMNR4FBCIb4ZVL7SCiYn7CKcG03B0KOcspMlhQ==",
    "c7a4Vay+lX7QojZpfe19ZQMdIRGVVDHqdhD/Qw==",
    "GB2i5Ks7uSJNIvw/nKvM6SFh390hCVDlObYotA==",
    "5USvlQBP0dxjzUkupDPT2jQQqExGgJuR4vqK6g==",
    "DYGnXw1q8iDuFG0r3QoIFB34VfqzM1/7XYDY+A==",
    "jSK78nvMlmoKGFaFSwwqRJKYV0hc0z+cEhgeSw==",
    "cboJRfle2xSCBOrzS0lRt/+4kn2Pg/yyJsphRA==",
    "XEZsfm4Uu04wTJdLTKhkj5bKMYe1PsVbjV+G2A==",
    "MWySY3r4205Yk/x0DBUH3OZrz2qq+z5ZII4ZBg==",
    "BGlzvSZ6CcNzHAMp6HdTh/C3u3MnUmmmpTjkYg==",
    "K9vag4GR6pN3eo01tOW/dHrGYLKkrUOhpWlExg==",
    "LNxt3Rot/n2vJfN958R5eaqKHgKHPd5g4RPgCQ==",
    "2mdS6ORwFAfTdp4paGYwEv+ysFyfs0BHTfd+YA==",
    "zahha85IS6yPJExI7AoEiKBiIbsJOMnRbdeWyw==",
    "nvPZIboypUIAHw+7bYUiWJfnae0ZUccz6lAVdg==",
    "fg7hCRBbXmB72u3Pgpp++uFmghoXnmtZq+OFQg==",
    "jl4E2/sW701YDX+ICw1U7OfZZ65djTUSJihGsw==",
    "GZOWSdwGVMNGb+nTIl+k5lDA7MX82lbIYn18RQ==",
    "Q1lzUI13IB74QO6W4qV4Ec6qSYpd5J/8A+XNIA==",
    "lC4rTnj38xCgZSQuBlLsVdcGGC3XHd1v2n9j0Q==",
    "N84mPZ4vKyO+A/FXM/Wy2h8DLTkY7Vot21qO5g==",
    "Afc4tx68F7B2EaZyeutKNDVpevnAcuoNa1FWeQ==",
    "R+vQ3cIBoewWIbpgnqsm8ol7iIQ3lYgI0G8Vqw==",
    "lhiY1xhSGZRQBfUJx8TV604DN1o5gWuEFcBpFQ==",
    "pQm1mBWJl9H3w392Dr2eR0IzICYjVeMIS59n8w==",
    "7ocaWFO3CcO+EEhVwzp5KMSRFGqp1NtCDGA4gg==",
    "4wtdjY3+Wlg8p0+aRUv7xa3N+GopOyN7TnLsrw==",
    "xmawPbKerYd/3kGluWXbKsxNQJhzJehB2nQv6g==",
    "jy+4zdn9WR88u6MH9uPqiS/6kJ1Qdjt+zPvMSA==",
    "QPakhKrwMzbobmvBqOdhl0+KDdlVpHJ+VZdf6g==",
    "9ewr7lkhIPe0xrjw+pKCkZBWKl50HtGa6Qs2Sw==",
    "Tn6MrEolGUM4jYjKBJ+MSUYoQGG1vej/knQD/g==",
    "hzrkmL/aqtvJXv2RwzRNl46xc3/vX7s8kS6bhg==",
    "TdkOhgZRniG5x+B8Yzzv7EvrMa6llRqOoJvVKA==",
    "c43I5zjU0ehm4wp5RtLiQc4v5dLJu+gu6KalQw==",
    "82QyJytIfd+gGfoguCz4tpydbtB7k85fVemaHA==",
    "bgEME9t6DqS4eEXY0D6546+JHwiQRRgJk4t9Vw==",
    "J/pj63nDLxpitgomCgl4ZYxbXXLFlElkNFgW9A==",
    "D3ofKlzURcmkE4VU9NxPH5otTb8eoaID2NIlVA==",
    "k/hweAtmNJg7NKok/Y3ji7vGo+Gf74M3+KyCpw==",
    "rCR4IZfzKBzk8jlud/BHh8e6N5BtSTO8kYlFjg==",
    "VkvifHHLWOEElVaq9HpN/bcvSrdifXt0IwMaKg==",
    "Cb0lorBLP0AtlVBVAAH4mSbuCyk3+fTYD+0VIA==",
    "qz4zSjeVPhj09nNzbd22ToUL/fKdWnuiaMVn2Q==",
    "nv3CyAzTinxfa/jf1BVGKGmqpv10NHqHwupAnA==",
    "HsMiLJSJeuFU9oNCYTg+QR3D7iOX7hFmndKrJg==",
    "McELiC8QTPUo/sbr7InfGVi0J29zE8bFGGMVaQ==",
    "7Oh4Fp4QUTKCp4ownVVyJdhSlPscu/8nQbPIPQ==",
    "WdDjfo7w+kqpU13bjNnKDIw6kezZxvZZNNv8Qg==",
    "Iv8fiKKl5UODRvEd+WtRuhD/ADVpmfQmWiDF1Q==",
    "XpbFygw0tRUWeIvIhGdCAMq5R8QBwHPcbA33og==",
    "fEA7LBuxDMvWEUTynDPFLLvnfCI2lLNzxGmWUA==",
    "1t2L/mK+55AzpBc/jeQiz/cgjbVNZaOdvGZsCg==",
    "QUg8KKFp2snRVD1g0GsTIi4QPBzwIxhYKoTTrA==",
    "5pQIZiw0y0jIfLhDdLrpIkXo0aB7CIwBLIW5Hg==",
    "//RRf3Z7kMsIds/AtYOUSi+AGg8kAHnQPyGpWg==",
    "bbFjNZVL9dFE28FGxmWy2rC787qcB1m/WSRjRg==",
    "2co9MXAOnawAS7Tczsjc2D9x3eSafZsg/9BU2w==",
    "q3zVRSpNHf32/0vOlp3l4Tm8gHYH5QtEIB2dCg==",
    "FRY11gvyKsqi2KfovYd99bT1wL2UlEeYj030AA==",
    "XpIGXdEM7koRv041e3X+AQzL9sUm9SzOF1jusg==",
    "l6vgEgVqf3mVTffBos71PoFvfDLGGBADkEh6Vg==",
    "Bw4I8TIa9G/dIFEACYK8P2jTQjltCql9ahaugg==",
    "CpB+koWqoQ47bhNLyOiHX5rqBxbQfDmgYw+gRw==",
    "DK/3Q4z+HW75vj/RUvO+hMZUYCMM5uZGpX6mDQ==",
    "RysyLzv+1hzk6qu/a7rw8PzqL+eagWeZgCCu6g==",
    "7mKfESBaZxUAfY966RuT/zmO6Rc/e2dsprdk5Q==",
    "OT26PtdcwT8VtSpceRJu745g1ngSBv0PLsHkBA==",
    "UVRsB0Y6tA+GyFbyUQlWqXSDzo0igA4Xev1B9w==",
    "u+fciQV3XCN/OLaxfWc0V98KSqXxo67Qqt6qgg==",
    "iLq0Ady6vN8O9XEqRUGoVRB0Hthst5KoUae0Yg==",
    "lGBuBRQk3sJ7Z5wQFZ8uunz0H0gFC8/PH1s2BQ==",
    "siYqo6oZ4vXCFgvoyEMLz3MW7mKUJk8biX6fqQ==",
    "R+j0jPzp6BiN9B7aJGEV0NELQY8Mj1oc9swM2w==",
    "gMRnKgORUXqSZRX2Btp0DzWZ+Iq8qB7BoCNbLw==",
    "8uMSs8tbXm+YVU/GEtXmW6dVC2Bp8by0sE2OoA==",
    "iguGRKK7N7p6LygQKMc2FO1ERWgMttF5hMiRGw==",
    "hJBogLtxwoaCLgKl9Td5txgZTxyH1fyrLmREhg==",
    "+i7TjrRDongYbW4s0xOW/oX+MHKbR5jw5iPOqA==",
    "SvkBi90UbDe3OCeiWABA/fEfT2zmsbm1pD1wkA==",
    "ILWRsOh2EVMAQGaOS6BJTnzePMf1TiusUrCheQ==",
    "8DKQGSgnD/gEcr2C9VxN49KEHyj6OfLv2hVOXw==",
    "ViLdGGW/QDrA2u4vFOtxuVblSd/B9L75BnO92Q==",
    "fXifdKdOw1wbVXnprMB/fR2sqYqQ1ERKV5LMYg==",
    "IdkbmbTomFK00ZuMR4IjYSu9fOP8yck+ZLs+rg==",
    "kE9ttOi1TjA8sgRZP2KVkFKZXyVZYVoRX0fA6Q==",
    "Lmp8J0d5AHhCR0HXF51xBOevBqOLLHfhCNnbyQ==",
    "NGUlVYD07hTx8FrZngRFMTQ95aUdg2gFOpndJg==",
    "KC8kdpEjdvVPl3O7g9Pbzbo/FlXNYOzVxCMOlw==",
    "eCGMp7K70NnAxcYxOYehBioF2lojNh+rTHK6MQ==",
    "eaeVhzF2Et8u5BQkqN/1BS4YkV/hGNjy13+4jA==",
    "wr7X42RA0++fAF2Diobd7/twxFBH0p8JE0BNjw==",
    "wLMXOJfonS7JNC3yHt697WFSYDCxXOTBnC74KA==",
    "4YGdSt9ulU8DhqU4lW6c+8nwBxHITQ7gD1bYfQ==",
    "oB+505N7WJ6YWeCmml/7yxAFy/XShyC6axS8eQ==",
    "uga/AgrcQz1iJQrQyO49DPEfI1t/EsH/tx1PpQ==",
    "ofJrIdqzKkO4QjIW2UtuRIc3W0E8rQL7L0CgPQ==",
    "FyRsWEsPNvE/eP0cQiCuqJZDDF/BbmGQKCiDwQ==",
    "FlDrTtp/V48Zjtf6zQA/A+gij+bk38PlCxavLg==",
];

// Test input is [ 1, 2, 3, ..., 255 ].
const input = new Uint8Array(256);
for (let i = 0; i < input.length; i++) {
    input[i] = i & 0xff;
}

describe("sha224.SHA224", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new SHA224();
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors[i]);
        }
    });

    it("should return the same digest after finalizing", () => {
        let h = new SHA224();
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new SHA224();
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new SHA224();
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 28-byte digest", () => {
        let h = new SHA224();
        h.update(input);
        expect(h.digest().length).toBe(28);
    });

});

describe("sha224.hash", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            const digest = hash(input.subarray(0, i));
            expect(encode(digest)).toBe(vectors[i]);
        }
    });
});
