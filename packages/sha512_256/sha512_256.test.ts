// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { SHA512_256, hash } from "./sha512_256";
import { encode } from "@stablelib/base64";

const vectors = [
    "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=",
    "ELqtFxNWasIzNGe92wWX3skGYSDdcqwty4OUIh3L5D0=",
    "LnU+cJFW9IIKJ9nOt5CNGA3QrxeT03EwN5xf+ck0X0w=",
    "2soHYqZnjk4my4qJPXHXLPMjninMg3YpWQuEYl3sFK8=",
    "bcBriuDLMEsYCHMb1ed7C+/sgJ9uAjeWI+4PAMELZYY=",
    "9It2S11u/nL8ycETZoqK2IN9kkWDKUjNoed3Q8nFAbw=",
    "ppdFn1nyIrBV4RHnkSEdoToFDuV3cRtO/yrreypue6A=",
    "OXg7yehZ4JgjRqeSzzFb+BtJLiWhLiee6EW6a9FENd0=",
    "IJcdJtD7kE1mAp3qAhokv4uglkk1Ye+Go/dehNMJFAY=",
    "pCUVJm3KViQKfgloOIDA7VruBCIdffxjUQeidihkcG8=",
    "X5MQ6dHXK9/Zj9Dz9ELzFuUQe0b7xn4WI1B1awYd29U=",
    "wZEJIBzpMU1b8Yc7m5gYWw90LeuNbSr9UmuAlTcadS4=",
    "CoUO8IKr7PmJmm5sVwFknHpMQVhBBTFcG8Biig9za+Y=",
    "DscF+yAr5atM0ipbtgFC6zOkxPDk2hHz580qdroQlwQ=",
    "PDPE5tr7l9RfQDvGYvdrVQU2Uhj8Y/I/pJdyIZz9yAY=",
    "epprBXVUaTalnd66cddv8UVHgHaQbv1eDUEpkBEC9SY=",
    "RyXnwj3Wi4stci8tNw9DQNE6CvQr9XT3QauKifq6bKY=",
    "Kev7teFT6Yzg//+D85WQaFIHvuphN0ZJbHXZhP7eakM=",
    "ge2JgMHWYjoqFMB4mNCqtppeic3+dWQ5v1RPEsuquW0=",
    "sIsN4F9z0LtA8VJVast0E9zkysWcV/lfow9VdPWgHts=",
    "8sk6WQhd+g5x1+li+udMi2Q4Z/h5nRbBQTIlrUzuL0k=",
    "015twS3jN/iYQKcHg4vp1c4TyDmoX42C+Sz/L7zyizc=",
    "VVEcpljnAB/3u8GTqpQAaRfUGZbY0FlygNqhVasqrXY=",
    "klYZwB54t3H2hAHlux7R/6aYrFQfuIqr195Tlz4gvw0=",
    "olcqE9WAOeqoJwhrgwktI1UQAls+luIU3ISLQkiMRqk=",
    "98C0VhviioupQbzAPn4ATWR5I0r/L7fVyitI8FnRoWw=",
    "NNQkMXgFq/54WFyfHBrAop8dyJnQvlczgWf/n5tHOuU=",
    "J72LKew3ynYbmlEAP13ul2f3/oFVETw5eWw3kFhiTTY=",
    "F85bj9475wjxqgYgmY/Xy/kXMoPVQyw7SqAhPUZrVE0=",
    "Oo7ogEthInwyJAhZGIgwIV1h2BedvUeJ7r25R4Hckbo=",
    "tKZHP5DKLof7MwmWqCaRY3RRWt97e7gTNAB9Bd3SsAo=",
    "grffSaHXvbCc8RgzchIjOc8/wo75dDuY/Rk2CSlzE6g=",
    "sZFeroSxJhbOUdfiWbeuw3mNQnpzW7EyJtBxGfZR6YE=",
    "8NrQ7fanx2HppOs8jCLL3X+C85G3T5Kd8K16c9OcRJE=",
    "Ncra151QwqO7DV2Gcno76eYJOiv4zOsLvtowI/e/ofU=",
    "c/XJm6KYUV2UB+BCwqVEkH/uwUci0ivFGg0tGXUCZb8=",
    "QP9o+bXk1hymca71G5lycToyTphSqnM/r9A+Ch56JIM=",
    "Q/eexdkjFhgfRnG0ZLUGn2j8zF2HAx0nOkfG47rbLwk=",
    "pqi9XOnHayFEPAoHbtDgWbUJgaVA83WGqkG/v6bq9Ek=",
    "FhzoctF3HDeMpyCOiZB3a4juTFt98yfXtoxXgaZ3ovo=",
    "yrNw5qzElKQWVbSHhIUor7VdiE+sakBHdftdTDBVUsk=",
    "YiS1TsqDvyUX6GLM7ahR14474Mm+0YW4GV0OvIVEnEg=",
    "Qtp4EqF3/dq/te9XBVQqrHMrLJuNc0n0FQcEvFGGlIw=",
    "XFHoG+DsOBdGXpaKoH8Em/9896Z7HTVeHiVO39oiL3E=",
    "mhhFWiRgxi9ENuJ8sIs4Xs38NFGqx54npisqao7gA1g=",
    "7FqQNip1pRfrZdcSDAUZTmQzeObcJZtQCcbnJ5wjuOE=",
    "yl84jgOfXg50FY6VmwKCsmarTI3YEiMDGIJSQpdALX8=",
    "0g3KVK5vtCqWf/KprmhjNaPCJiofpPPiGUhxMdZF2ww=",
    "LT2TR0XTlwZ9Y/CwXey3jVOS4IkE1azIKHsM22l+GR4=",
    "rkJ5MSuQH7mKsPg3MOvrDDDs2i4dGqq2IAi6U4SjC/o=",
    "rDCPpdz4ViTqGG3kCBs78LnrdU+Mk46ZJmgmOoesA70=",
    "me6AJLqMNVq0FrffFikQl1JG9hMjBh7qZ+zJwaAA/S0=",
    "d3O0zgjp34X7CxOPmadu1CFmjtGdDvl2bFJSv5r85KM=",
    "crbXEN7N8JfU9/vULdm55Vldl8gdQ226L+yW0NcgqZI=",
    "rNIhYNiBJ38AENJXWuNmewsXCZ5l/jTMp11XanIeU9c=",
    "fdWKfDKF1kNvS4h2pOPOY7rpKhGlRTxGpgMsXkab9Aw=",
    "wG0tT20iQUSRs24hXeNBeCki7DaQDPyjn0pwelN59Ro=",
    "mwgQoDMOBq943AjKSRvSSP5uNqHon/e5v2WqyedgWA8=",
    "6XrQ7BZHEugQPO6t/GzT9x8JQDUWF9OXJupe9RKnXoc=",
    "eTItealbYPRvLqQ/lDeMWbZh5DO0u9NZVzRYb9NU6T4=",
    "tSVOjh40m2AEDHb2/jv5uB/IPztCSfX8Ag0b0YLB+Bg=",
    "m3qQzespeRBwo8IrFNywRVSoAqWkQevQpVPSxxRky20=",
    "0JGavaUUx/JG3cnm8QTWHMe1czbj6KZY2d6BSZQgezY=",
    "U7U+x8DZgLeYDBakDT9/+DwQONAwC3MTWE3lperkSXo=",
    "yeSDuWIlFegyWeHgdXRrcBQssSF4Y/uMhfrjMlb0GIo=",
    "mhmDQphFp/zzGRsV7fy4oGggDeYiT95nkdpMl/piWN8=",
    "F9OEbCBIXa/gyAfQ7s9awZodff5esn1WnfFsvqUumBo=",
    "eblqBtYajAi546IFOj2ZCWPh1Mv3zPMWDkdKNSj1yys=",
    "WEgrdHGVgUvpnw7TSvmqFxGE/CWWuxRxQqeGP9GNKzM=",
    "1befK0m2tQ3ZmriGo1l5E8Vhyw7TcNym/fOj+gBXCeQ=",
    "+cqxgaQiR4+XfVUE+b2CTDCCSqzioda58fkJhBqvnhI=",
    "39FZj9fJvrPEZT3qLUtIDIfjOn0M6x2X3rTFlj31PRY=",
    "QA9TIsD/Q9xSAGILw3/0qeJK7lYTPPfr0UWjnsJRov0=",
    "dC419RO3yXKNmaEekjcdi6bolv6snYoNOeRJXMJW2Sc=",
    "qrSUnlV4OYAqaVN3aA0FUDrG081125wfjoqeqzgHMZE=",
    "XLjxiU/VNHnjKjeAfqY03i5Asn0BDQ77UanXIFaqvu8=",
    "utvi4h+gg4jj2DcM5SxLI4/2CUZ6IQtV6FopTqinQsg=",
    "9aleii2zPEHifGMRw4ByhVpEmkZ2TLBug+IAn1WplpA=",
    "xPhZYeNXO6oNemQcVP2CPhyxStCoDrOexRUgw4EZcbI=",
    "5e3Oo+8U9ilx8qevmES6CH+xt4inHUWy90La/qS7GZU=",
    "7yxSAjAbRUZPu7ILYg4dpk3TvPyc9wxHMANONFT68Wc=",
    "e2NNT8Q4pne9TocPawMv+1YL8LjD3XJdno7e7CFexUg=",
    "g6civtGIMFBiNxPstVeVgnmPLcV+AFtxJgxSRHfuIC4=",
    "jrAhyMiqcPfErUiHABTMfB4UVYREDNQ1iJCFMskre/0=",
    "YCK8jYRq9opGV/LWvnLc9hsc5DOD0jREuVsqrxRacHk=",
    "R1R/K3eJix23HMRWWr/lEd35uWX6+P5SKzRtWyNraS8=",
    "W6gMZEr6uYzrnABgd9oRDlLMY8NB8JQSKKWZK+jR3WU=",
    "prJfTp86xXFpzgOC2QsB9NzA+MMsJ6ykoveQegE9M/0=",
    "2FG9SftCCRS0juATgg4caHBjKAKS/D2xm6Fzbdba85g=",
    "W5daNOc/9lZsiR3tDLjH3kr/aSuqCSckIJjr59s8nYk=",
    "8sV04tjLsEp9QOXD0TVmexyHh20NLWu7YNTdfFaF6bw=",
    "GzN+ane1oS916XEwDD1FpYs8A8cYXyo0g7WpbLrE3Ks=",
    "Svk22BmIAIMV+XxXGY4ATgBcOX9a9xO03pHDYq3u6ic=",
    "cjEI5RC7lba4EJbprdH0FydGsR7iWyDsDXAk7amPr/c=",
    "RBtUZU/KdNIbGB7gmUn/0IRn/bRoCfVIPctKIhVcGe0=",
    "BSaIDeFt84o2lAF9cmxIi6kaNnmHZo03qUGzAhJ/nrs=",
    "xCQhkpUwNqvhnQdxnS8cu4/wCIdT0lxYYyyeLGAPVgA=",
    "H9h9pZdGnb29k9gdqfs2eO4BtrXol77V3sWxegdwQLo=",
    "13QDkx//YbKDhM38OphXJy00UmM7ms73A7Zo5WRIfjw=",
    "GUiK2pTxxM6rvgfEB7/Vml9S5Pjulky6ZEJjbf8SySU=",
    "HmhxeZvfKzk3+EWNEkxK5VrltCmO9qg7h2MHD04qDz8=",
    "s1KaCTyuKd9eTuznKa4FP79FeSdt4vkIWcV9lXn69tU=",
    "fqRNEmy5nutPmFcJuvYgFaqYAkQtnTUtIfx17SNFD1Q=",
    "tSVjwXUFeWVWX49jRSgvUEiEbLy03JIGZMvsWFrtXfQ=",
    "wigqxncfJlEWGwnUje9kzDBavJhkTG9nDS8OIQ/J0W8=",
    "VEkbSCGC/AwNeztoStirKRZtAH3KED8LJFnmg0/73Z4=",
    "G2c/sz1ajHjl7pW419uyJonmZEzDr9Y0plunnvtH3NU=",
    "v4RNWHZ/pcIhQi5+EqjTO35Snm/FS3GBMJloatrgGTg=",
    "3UjAEkRlxYWXm02HTr8tYqDdqZT9p7fbelQ1KzwE2ao=",
    "+bRYbbgyDhoIKTxcNiwCNLpbiX2aJDA/8VMJ40cSuJ0=",
    "2/WIZs3DoPEesMiveQjE/v1MHRwtFu7OLsZ6cuPVmfE=",
    "vSCfYLDQQQKgkXUpf9JVNn5UtaVgW5KGNcYGMGkUNj8=",
    "LK/rCILMQFFn6aJVuFgaZtxoMhJHSQLdRT28ogqU5ho=",
    "MiIzO+AZ3JleXdFJbVhZ3apJHgPn34GmWdXnSVe/O1M=",
    "LLGUNLy+20LHkxHA9Urt5XTNdUGJcHUDHTpQYeq3XoQ=",
    "VERok4qRgy4UkXJ9aMTYguReTFPPLpTW+pctl7k4O2Y=",
    "fseKq0jiQWTy9L/lyYRJqGTCHmVIhmqSHbtBweVjOK0=",
    "KR0WDs7Iuwp1Vf3Oe8AxAGaVCxaM1iIvcLKPHqJ4HXc=",
    "DqiH97L/KSFUhtz/tjNvrWmN/ehPqqeBnDIpAldgMJ8=",
    "b9zBpELMg5HX3VoNtmAe+u6aSVQFbHimQDjDa/ess2g=",
    "vnSpCrvC6gP/Vt7a5O2hVLps8k1zpRWQM1YoO2U/UQk=",
    "q+yvM5H27VSCDe3UAiGmotA0Yytc/Znw5BXy0MSHwrk=",
    "G2LHOK0IkLfvhiU+6lumEvZfnBBqBO9/j40Nor3hpDY=",
    "7RkJR3fTOvb7v1kXDjKZz/osfOqjlLY53ufmaR9/I7I=",
    "cV3g6MCeX95r2mSXHpmSoRoincHro9vsqJzx2nZ1fzk=",
    "O5Y5AXR6MlYmnQekduTj5sdM70Wu3KPvOYl6PoMwfFI=",
    "HbslN/nRx4nVm0PBiPAUjE/wDkVF8V7vX8/bW5x3Gp0=",
    "wmvH6TFeYqsNxq61d3JNB8CbDG/fwKnwjYVIBHwDIkg=",
    "L/ERlLKuwflDy18TC6ZHwVEzQGgIMZTXKBpV1geuJV8=",
    "xKO7+EHtKiieUQn7OSIpyA22HHL9kgebWk8EQfCVoRE=",
    "6e0UghMPSdePH93uswyKjiVfkX2q6VU5B+lbgkJVTE4=",
    "Zi8WiGBnDJR7CVTpnfr6q+V87+eE1IUr2LL48BGKLW8=",
    "pJLJChZ0AW4KKk1HqQkMC7SW2qV7V0BeNL7SpZasXQg=",
    "W0aK9xAUPdmTNuvjXOxE1HKBFH8RegYSeaxgojj98PQ=",
    "yEFABI+XorB4MbxlSCGzFqEoagTOzuzMFy8MoAOaiG4=",
    "nUwdrwb8E9TmqkQ5r1ZZHoYwL1Ro7S/YPfXc7D61t0E=",
    "dEtt7WiA6kiPodY9UvHlpJqDQKcGxJrYHAF5iK8g0qA=",
    "ict9ozOw/eRa5FlQZnpVDkfqQO5ekPJM124O74xSTE8=",
    "ftMgzGSOcfcDZF4k3ME4zNcJsswwHC21w65aEtx9Qrk=",
    "WvrZeEtHCSQBNkHeiz0CLBgbzVTYCfCmT+2yxFaJl6Y=",
    "5QMUOpWNljv3EJXSDGHeM0QBenRWVO/WQMif5eB6G3A=",
    "4zKIenB/Kji/EjAbAppdZHKWLZN8QFaETjIk7IDVe2c=",
    "6m1AMRgE63LXsoyB/ttvkmtyMqyMZoEa0Tgqi9TE+EA=",
    "yD+OoZNJg1kYPrimaVg0jl3L/Prbqt0oxwICOLvAszk=",
    "RJBDo5azpI6zRnYSmBqOZm1g3eZpGlTO7XrLDm6QHKM=",
    "l4upir19qRXLgv/Wjmxy7jNhYICanJjQtz9tSlotU5s=",
    "t/4pelqO74vCc/EE1+q2o0Z3O6oMg754zqEHPuazthE=",
    "PNKsIVZrcX1nt8wqwT94g8LwXWhx8KWfor6NtaETke4=",
    "J2w0/Wamc76zDpCzet1esn2MB6Yde6yri5SLJlCpetY=",
    "rcR1aix3VpJGO54l092+dnk1XxzXwKY8xbiAyerMN2M=",
    "JRz/0yHPN9m4AJDsGuKWpFCwW43RUdYLocnNY+DF7co=",
    "UFUACOu7XIL3dLDG8roeEM5BH0S2dHVRXX1RV0Gh/xk=",
    "fvQTchR9xWQDuO3eKSfPftnCrHVdJM+7OnkvAqfh6bk=",
    "KboZCWKDC+CKnSbb0Gs59AmN+69jaJ+3MgR8PvpCJ/4=",
    "aZQ3V6iEjcz3Gs7iQDDbi/MqTFeZ6gGIvepvhZFeUwo=",
    "z7I1qmiOIstwgsk4pMH/CsjS8IiAWKa3g+v+U402xDk=",
    "n6WIqUyvsbklOvKyBDvuRbEcIvJZOa66cjsYyLUjFVs=",
    "1YJvbxMaaC9ubD7GbwDEUd6ZdqdCIfAx5lQfntluZJ0=",
    "t1hvdYqNOSZI+PrrisF2ljL4ElEtB97BuKxBEO+TICg=",
    "frvlMIWg7PMxmITODbT47HZHN4Phqy/6lT8lxuHnaiA=",
    "swHDzIFc0jZuCzEHTrwGEZQA/biTW3E8pqRFB6uIrT8=",
    "5F0zEQx3qxRuadIUz8KbhSECfzGKIKYX0PF9kOWY9qU=",
    "XNAuYuUGuL1tALwqfUzo/OUhA7fyw68KhdH+5S1zbJc=",
    "xfFVGbKnEiImXaMQ5SHK61DKuyIeO81nZtADfr52g4w=",
    "j2GTd/IKlBWNCr6qB2/FkfRLHckXUkzfpuikbVbWd6g=",
    "yA/eG8sKOT5ct5xBhWXh2hWyUgz/vb+digePHj2jBRs=",
    "FFqijf18IuIUbt2mFYLlnN+zRhwDTiGnAh3+mofrTwI=",
    "h8siWzPw0eQ0LMp10LaDjzteNjlgXdtsNK39HwAPNig=",
    "ZyP6RtjmYNWN8Iq8e47MpWh73PzeB13SYvNRAz8ps8k=",
    "MY3oKqUrJ4bZLeF4s2hWZNF8CBk3gDeSzY5Y0VsENuE=",
    "GCnNQkEG/b+kywYqp7Vb0JM+/J3i/Rs86VE6IT92BRs=",
    "NuMbS3zL9ITEoeXRad6fcm44RjRNnC1/oNCb/bbCbfI=",
    "pn3cQV56wkCIxyigyQtXGJZa04B5C5N1hPNKzkHsWZs=",
    "QIUXxeiRqClY8fsjV61GZorb6cmmJJfmJfqZ28mzndU=",
    "94zRSh9EvMso0FSWWUbc5OyDCusQ231XRTsAljVMdks=",
    "5+GTV6Zt+vY4AU+i9o+Xphd0ORwN5tRLyLBP1zoHQZQ=",
    "L0N2S7beXzcd5w1dMhQi0TnmgDbM9L71SM6yTdDo9/I=",
    "hC+tYqC1oFfdldihjruzjduU4ti+jL6MsUMDUibz09w=",
    "0rXhAOUFB6XPqB2CsWdbNGzUchkueBsq9CdATWy32yc=",
    "BUgNFySAJJheviLLybxP7PaA0cmISaRe72UmksheUSQ=",
    "RIZpZtBsj8304HB04TCbnabEmMX2JPpx2hLqkPVlmZQ=",
    "5moPuhk5sl5TPvsdoeUJERsbLxNeKzldx0EfHFmDlY8=",
    "fP26XvxessViKTvBEC+cz/d4yreBRaPSvc/UwpxfgNk=",
    "zfBfKhS9AROecxyC6IIapAlJcclcxqCMfrRkN0KjuHE=",
    "UvMCNMxvJLdjfexxJDqnDDEwvHRZOsbHlOttWvVjsRo=",
    "enkzxLer/suNfR/TMaFa+YUSo619nZw/I7+Z8Ymhx4s=",
    "ham7YCiUV4roPxjhrctj72+aPBOCi/ISx1GihbMOvew=",
    "nE1+J7IB1rRXH4l8Kvt+lQdZUcyW4xwB3CJLqQSmrME=",
    "q7iY3msZ8EPZSB5p3ZcGkGGRbgXzQV3PtXZoR6kj+as=",
    "jPJiOJ1zETWVZgPeFCnjUpBHgjkWPxe+JtkoUtWzthI=",
    "um2GnO52AV9FIStBYTpWeYXZww02PpaJSKBxkIQfO1o=",
    "VSBDfPsCRtcnnKAa/zyLh6eyKDCaDAxkMTulSBLeb9I=",
    "8s7lddE52l0MSaiI7DpXPz0oSWaZ/A88gsabL/LMj9k=",
    "Mlat4y1NF/FnF5oRu0KIiniw8Wng+QBAbi5lJ/g0EPo=",
    "BDAgWyRAINE6Tpn5J+3mNj5pzqtIb4mWdvCS/hAMjiY=",
    "a2sJCOnB/umLlarlm9petvLvFOu0l0cXXwIk8WpyaNA=",
    "XMJEu4f4sJBY3sVrP5L9oKXF/9N1xF1LLGJZ2ec0FJQ=",
    "hQUxfwdg82tApngdv2CVvuSkw8IHSREHwqj3Y2hXglA=",
    "x284fa4hDH/QMOWR811zUliILHLIR6vit71+C0Kooj8=",
    "KsLpUgJ3ZyRapOrFU+Uxs+/+klgpJPyyHZ5ufmcFQgk=",
    "5RGqZdTlPAu2BlyeHSiCJIMH/EmH5n/KGNfjx3AX32U=",
    "7fj1qVsabz/4q2bixqGairQHQ6B56TZRD0AUisc1vxA=",
    "BTrsejDYPb5GnY8mgcExR/ef0N2fGhoL5JdwhFGQXS0=",
    "IUM/upsZOe8sSvomvq5TDiAl2inqD26mjAvhJDNRe8M=",
    "Uuz+miHEbpm1zZO+lcgjxYM7wxyrQ4YJQYtNf5+FY88=",
    "lb2Ab0VxGlWu5213TNYetSW2wL8wIE9NgDLjVRyYb0I=",
    "s7VfjMF97lS7EkT7svjOwwRCpbQOoYQdNlregRsqp4I=",
    "4b2/Z+tUrOnig9/w+Eg8/jcjYuq1AkOflgq/XWdGUwA=",
    "1H2zl0NvXwoqei6L5BqpQi4mm57XiF02FDq9xD39ZwA=",
    "e7TDuFryUmP/4dJ14yh09/Gp0e+dHWD7SCPWv6fiZKk=",
    "yckpvj5Dc5llx+BnS90cbqcsUCl3R9O/Oq1C20fi/44=",
    "EuEBuWycu2/zyvcFxsv7ifwjqkyWd9xa3qBntvCgf5M=",
    "oBpu0EyayIvWtjXcHqlg8koYYWc8bIrvv89fOV6duwA=",
    "8ydpssh1uf+UvbpJZ9Q+mo/QV9tubDCvc9GTtwQ8xxs=",
    "nfur9TrepB3wE/fegeDLP7RUYNDqBaShGPlHNLXEYQg=",
    "xk8JmfckkdXSMZNPYYUtSoBRXYtDORm8QoqXRgyscGw=",
    "cn84tnqsn4dpxqbcj7Xd7lnrHXLxUThKPvhLDQAqldc=",
    "LzdSsYVqQadxRj/obTNpH85zZYtPTQYYJnhQF1Ql+lc=",
    "SpjhCYYx4A9O+EmCZxcjYWIwvt7+Ji9LhVKUEKFhA0E=",
    "UxxGiaeZ79MM4qLX5ALcQRJmLiy9CRR1ULrHT5txDks=",
    "6ar4oUrqe3CVto3x5jv2Hs8j3jM2zZSc1wCQEeJodcw=",
    "XWAWg9Sqc2ZhvCrT24682AV4JzNJWpc/OVK6XPonKoU=",
    "oyKv/8z06/wSNaLfPvQDfT+IoALSIdJlilqBOkSZhQw=",
    "7DDQASc0gqLcLTYstfajPCFW6SPislDKOFcT1MCwHXg=",
    "Km7RTlOVCwzDrjbBV4Katn2JaOwjEzaP7RJ37JbCAZc=",
    "AQkMqV5ECkNjivSQvdqU4a6nsEPey3V5fiysBPfbBkA=",
    "oYM0gTRXslYj4MkM/lt/t4u487Ars+8eYPK1xGb7xL8=",
    "P4kwK1r7I6xmxcVd4CiAtm7IVZ1nhStm51SoGYNb5QE=",
    "hbIRgDR2wzuEX6g+iPp5GFwZclSnKkE+3FaNH2hJzDI=",
    "CKNjtcJjfQ8i5qJSyFBhLWYVb/J4bj1GfoB2citJuVw=",
    "wQDNTXCZJfzKgOTZoXPFYHY4GCwXRFggiv7/I7SzwgY=",
    "Nz6gx1SIrtUYBLbmwcgEE8I0wT/3XRm8urmGTrt8LJA=",
    "rBw1BFjyB91Y37O36ifrZtZ35XsJD7KqzpjIW5U257M=",
    "oW/4MGwPTnyYql1SKHStiMRl2OGhVqPZ2VGIa+6yxeU=",
    "pL00O1n1q4hR+iulLNwNZvrlwMF8EI3I94wlJNL5LVM=",
    "O85Suiv1YhWtRcxmqvvGHgoy6ti1wLUsr3i39HvhGLA=",
    "xqp5f11JASjo7LeCjvVlYF042sXSUyuHuY4BuCtZAVk=",
    "QPI2moQJqeNzrmHzn5h1RBkle41gLom9ZkYUXM/c330=",
    "css9X1R08P0q2JtYEaE/n8paxRTIUKGaJ5hLr7Vx4KE=",
    "uBRy0lXYAYLhlkgeWGaqIHdhoVIwKgI34kLriMV3pCg=",
    "bKE8VYhrdKXKKsl4LEuaSf467u/fwM78NJhIcvtMVP0=",
    "GkiORyaJQqQbVzMjgob7IYrkXUvZtZtI4cIEeEEJQ/Y=",
    "mN1um4SNIdApR711ttIgyaquIK8Fl8UNcIlrX0lK3ME=",
    "qNrgaC4qelp9e6wz9AnUojd7t0VNpbRwjzf3Q1tSaH0=",
    "IczcXv9b3ZbDLSedUTRmb1s7Plr4bQpW4Ult684inYI=",
    "afN9SBhqTSQyZ9jdBkv8VJiRd4NKD+rPvfIhYNaowtw=",
    "ys1BefLCqgAgenDbSxOXwrDyeLX5JutqMuo0nazLnNw=",
    "2NFsjqeNfz4EcBYnO0sUXYKt76EBewfSWzbOrPUma3w=",
    "WugCHoQqsHGgkYQ4z6fRUiWBmU1CGDi2H1MzHlgyE3w=",
    "44ciFMzqf6SLWzL83+tTieCv5sH4Qs1HvOvlL85fPUo=",
    "FT7+RkJAfyellcO3irJTXzT/19qCAOgeOvgCfejyN8M=",
    "B2QQ1jZUYmxK2haokRkYogP+M0VijUI3y26t6meooHA=",
    "AxwCLyNDCKmqXJUyrPVj8pn5pj2DU/KU/YxG0bvWfUo=",
    "cY4zoqdi+Z5/EUbVo6HpYVZZPsrRh4kR7+oRrRW1/BI=",
    "0M+4pA4TC8cJBZA9Hqjvx6HdDffjWBBHLfqzAslIDEQ=",
    "/ZMmFPN1v3FCBTCmkMsW5SwI6Zz+dBrIQ2/KjIv9VnY="
];

// Test input is [ 0, 1, 2, ..., 255 ].
const input = new Uint8Array(256);
for (let i = 0; i < input.length; i++) {
    input[i] = i & 0xff;
}

describe("sha512_256.SHA512_256", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new SHA512_256();
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors[i]);
        }
    });

    it("should correctly update multiple times", () => {
        const h1 = new SHA512_256();
        h1.update(input.subarray(0, 1));
        h1.update(input.subarray(1, 120));
        h1.update(input.subarray(120, 256));
        const h2 = new SHA512_256();
        h2.update(input.subarray(0, 256));
        expect(encode(h1.digest())).toBe(encode(h2.digest()));
    });

    it("should return the same digest after finalizing", () => {
        let h = new SHA512_256();
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new SHA512_256();
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new SHA512_256();
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 32-byte digest", () => {
        let h = new SHA512_256();
        h.update(input);
        expect(h.digest().length).toBe(32);
    });

});

describe("sha512_256.hash", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            const digest = hash(input.subarray(0, i));
            expect(encode(digest)).toBe(vectors[i]);
        }
    });
});
