// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { SHA3, SHA3256, SHAKE128, SHAKE256 } from "./sha3";
import { encode } from "@stablelib/base64";

const vectors256 = [
    "p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=",
    "XVNGnyD+9PjqtSuIBE7eacd6amimByhgn8SmX/Ux59A=",
    "dqtw3EZ3W2QajnFQewcUWu0Rrl78C6qUrAaHavKzv1w=",
    "EYbUmkrWIGGPdg8p2ixZOy7CzCztadwWgXOQ2GHmIlM=",
    "M7rVQwiZ7W+L6vPnMrKiytHUC3yd4M/Nx+C8B1aAOhA=",
    "gwXUZkPwQRbdyBb5FUS33NwqLNNKAlVJi+/OB5XiEgU=",
    "7SR5+EmA2EbNEkR/JBBZrBZ5rDBYREPUAiL7fhY5QUw=",
    "WbGt04i31iXSeXiUpNiMdVSnlqWj2K4jK/X4a9ctV1Y=",
    "600PKt0PbQsm8MZdvnH+YXzGtD+0A2SegsyLq0EZX04=",
    "UlfjTXu5ZPWa5KRrO6WSHgSlUMKx4E8miyl+NY6rE2I=",
    "YFoFFAWRkuJtvwbPq4bz6bu5ppNj1L6SWyJG3NhlmpU=",
    "RYWuFmhz+UqJMIgQFP/RTrzawaDVmdxX77SYm0RHIJU=",
    "SsvZLTEPw4aXCEwbx6eVFqm+IHAdro6zbGQ/B/Re29Y=",
    "FU6HWQidF92kVfdLv3Ar6Z9njViuRC6+FiZKeCKooEg=",
    "haPU5hIp2hSQ5kCT5hGKcz4wIbRnglYzX0NyUffSIsU=",
    "icJez9rqhbLzYMFaLs8x8L1ZoM6CGhqsMeL3MJPcTNg=",
    "OUYtKiMg+NpXKpews5Rz1DEuAiiyPiwv4K6bbGfyNDw=",
    "ajdlejJWCGkVTqqcpZ+2SPOpa2L1va3WBL3+ATN4MEg=",
    "Y26QTHJnDvPXjZ8OEhuytermnoBvoCMUaI1lYAQkNJ0=",
    "atDbIV+9MOeuXiLChBNXYk1WBbH8n9uWiCvUJSnmqZQ=",
    "2zI4Cr4j71HwVHrA/E0JWioWRFoA/Yzi5SYo4Ym6Vi0=",
    "MxzByFHfhj6zZYYLK8dufh6SgmG6xvGk7Aol7QDQ4sk=",
    "n1V3unUyQAfNZvnX8Wum50MT2FPnkfyGWqz89jxWF5k=",
    "8OhyyBAz5n78N9wlhDWWag0VBL0UwnUCdgkqvQ+bAWk=",
    "Kq3jbOtXDW06kv553NYSz80yJvAg8gWnT7EhMkTsSFc=",
    "W+dKoyPMEJLRpzpXRJZljLtICfQSWtJ1/BEumQu4wcg=",
    "tv5G4NyrNSvZ1NynfNyItzMAGtywiVljMHacxr78G84=",
    "XggCMc86kjk8KH73tZUNA5R3RwD4LyoLr/fqglJCI/Y=",
    "ZG2tpaSSuetknldvl2oMx2KAER92emOSHdKcCc1KtDQ=",
    "ICIgLmZK5rnkaHBrRcvqhRzXo1LWN4I2rG4NopJOmrI=",
    "eQm71h/2xNBVJWLjpX5h8j+4KuqZybLgBNlPwho/Sc8=",
    "vimwInMqLjl/4DnsF3ZtozoW0lVVUCd1sFd7rLykBiU=",
    "BQpIczvVwnVrqVxYKMyD7hb6vNPAhohbd0T4Sg+eDZQ=",
    "97gwOf+RXuZ8hYa6LUucNIcz2cdYYwVu+kWB6AoJtm4=",
    "vW1FDB4gcuYUFS1eY0SgzxT/sWrIZY1oF2468Pc3yaM=",
    "icLGppaQM197R1xHxi+TDIvFj2rpKpmv1Nl0PLI6gyw=",
    "ULXQn3Sj+5sH7cCKYr9UahQ6GtI0/P7wo4a3ikhpGR8=",
    "jhcRLGyxOZoGRDUJzMlTZsKc1y2tchmMI5VoXFb9Xx8=",
    "SRDiMR4Z0wdI844mWhqtVOCsyJERVy6lSMG3HijHSyk=",
    "hQEDuNCNVmFZ0Lv8F1mH+ZF5D+yNKQX57jh5YwHMj/k=",
    "AroyTTCshUeRV5vvTTVqbKC3cpkF0kEFi45acm50sPM=",
    "G/Iy5nuo7XLxu7SQOyWJy9+ogCkqretBazAJNDn/JHc=",
    "XVpJ3jU3o5z8X2dxZgilASoAPV7OVBajfe+OZjEQEG0=",
    "LTu1dzCxZxV+uCXzhTlxWD8YJFa5H73XUBTcJxiHOX8=",
    "QO2NPUDc7V3eNYFj9zorS+NcYJUiYggwiAz2OB6u3SM=",
    "x7gsQZmogWLVsEpCefmlnfz5cjnVu79M3uzztHXMSos=",
    "8zgpKm9E+XVGd07pfFeIFfKnvtWv4DaVLaBnf5Lz/ho=",
    "subAHi0Dt4vXHD4kaoX7B2sw+DFZqkOsGOM+2cwjKYI=",
    "jnqFY2X3nkIASqGkejuD6ObQ69u2AvYnk+V0E5ufKhc=",
    "oltq2CJvqakxjLhsx3FMsL6/3mwgVyute4mSXw0Jp+E=",
    "V/oKF5tRAkaz+NGVrLEDzchtgxVYgyXvU2xH//J3Jlg=",
    "XPUgKXybBqrWdIOYbUwBinDGcXMFm57CDeDE9YJ4/9M=",
    "Zn5V+j09av08o69qYAFlmOvysemLWccCIJwkezNgOUs=",
    "UjMCjyO1urQAXLhuoxsWQ17B9sj881dYD2eJ3XlfHik=",
    "geudv/V24yNndtQ7XKyduhBoXKT+vbDbqBYNVGjxCdo=",
    "qRoTjjN00tj6R5G4OpOjEaBqKSbvcBU0KM9uGyOcENQ=",
    "0ZL1lk3HARj8rGS/Drg4AJuBbTRPZ7BOjnjVveeD5Uo=",
    "atwZolNG05QJwmRGasfvfv5KiOdlqL6qGRJmeRqQYGQ=",
    "J1qgfObWL2L9ZuR58wDABUT2lyULbXc/kb8G4gb4iSU=",
    "FYdrFftraW+J54oECscLrPDvDsGDiaXEyl1tJAbCJFQ=",
    "PLjQM61xuZUawJeXswZUCvm6eBnP7WeT6d2myToNNFg=",
    "gpgkdm7dgg6JR4RcmBMNGdsOKG+0ZTRJNjJrbaVjOkQ=",
    "j/2EkxLPWGQLHfR66P7l9DjMw940LpKoek9uaewnCHo=",
    "unr1jSFLtgS8qtQK1VzKfZgV51NfHJg3vo+4/uJRlWA=",
    "yK1Hj04d2dR9/DuYVwjZLbH420j+nN3UWeY8Mh9JBAI=",
    "mhHxNdIjG+jugk0enTIEAYhw3vwvRp8071lptIFc7Dw=",
    "C77Ke1v4bYTml8DlLaSCufC4u5DHTFnGNY2lRYUnNV8=",
    "zQ52P4fIjNFi/pcfLwesiINizMMycsLnnk24TIkecSM=",
    "rZPGhtvqQW5QacrRyp1ieyoEDpw9nNFIyT31jdAbHgM=",
    "7TeekBLx06T+9QlmiKJVezzraMYZJFv/zwWhSlqEb9k=",
    "l6JrDoBm811AC38Spq5iopC8HKaGYLTai/F6+ta4yUg=",
    "iBrZ/71/CQ76Ucvf6T2iOgQB9ERvet8VDRwiaFHL//I=",
    "/liGayiTxsQO6DLOQPtutMcP98R5Q4DZXC6+7GLezTE=",
    "eXBhs6rY5yR0DHncaX7z3kyWxNtEg9uk5W+FIiLHJHQ=",
    "ajVDuCyaFNhZeyuzkWFZz1Sk8zMq5V7JcGl5urwgZ1I=",
    "1G2+7dOJvshi73Qx+SnO34G9CiBXO1OeEci+lX1rKG8=",
    "ZEMK+4m107lE/whdNEqW9RREGWLisoCJQ+gVk3j94vo=",
    "mPuKxe96WPB51BgVSEsZZQCE5Mpo0VQNkM3fU2+kcLw=",
    "6Tm6QxxucD99Jv0OtRHvQaN/brOG6AhI6rosPVvgH2I=",
    "gKrAUxvyfRsOPnRsNKhtsJUDY24hHlnFT5lSu05DaE4=",
    "DjSuMtBDJ1tQ6ang3QJKsCQhPwlspuW38WtSTws3wnE=",
    "zqpWZvxb0BU2CjHv8EmdKqjn+oORoMSQ6AbXhan4DFo=",
    "boVYliH+KrwSFKhBsi/2Z+C3l8BO5zbagZrazPQXbLE=",
    "Alm5HjQoKJJJEdtQccENiQ/WXChwOgAM4uqzSF1crsU=",
    "FxG2uOGWsr0Yi3GzIHrisD2bLOQtZZP4FtcSdWezHT0=",
    "Y/e9SBZXosDam4xdS8N5UqpWg2LNJwVQScG0O8O95Iw=",
    "n40rGasGnK+lf6pn06d5b4gPNelaxx70ZjEjYW9YUkI=",
    "2VN1/05r6AlEr9qSgZeUJZx9oxsalSownX662kp46sE=",
    "n9NzVSyTptkEv7Z9RfexdFMMPve55x6Ey/sy3+00gx4=",
    "gyv0Hmw6UcB7niHBcFZYfQekUBLNtf8hqe1/V3fio+Y=",
    "jzWt+Em3ipel9x6/F8ECUh3NhtnSAka260f3i/V3gJ4=",
    "9Mgtr5IY8Uw37PtQ/iImRPrpb0OZmOmQsahJLnve8Ts=",
    "YLBwwpbMZJaO5eT2VhfQC+Q/LnevSZShLWooEQxYbBY=",
    "+UmW2CFBr1M/kDvm8GEdLep1hKiVvnCWstw1CXsY4qA=",
    "gF4fR9BiRCg9iPMrBGypVVStQBgHbHSA3tPOfdOTvII=",
    "eASvTlHgwc2vDwpvrGZxsmBDQIH3zgUHC+2mO9rJuso=",
    "K+CvkiG/zay0uIMh2MzJzrzFMYjs206XgTzR1Md1xUE=",
    "5QC7Aquf9p8GjpzK1B8L96XBdvQRGfpwB5HbEgkqt8Q=",
    "D1DJ81OPDjVkVyC7UdkZETimysZNn4NmCVfUQSq87IM=",
    "BRht66Ind/52UtUfJK3ijxhJO4CSNtvWCXbSE1deL4Y=",
    "jEbYkBrmkZ6wAc1KmQeiKqpHlUYwCZpHPS1TNup2ieE=",
    "r1BN02/rZmsW/lUxFq291gTkScp4PlSoMXGu593H57E=",
    "mGuBlEYE7zofJgMqBFN3d8Ds0ctms348pumxCL769Ww=",
    "EgoFXFktI3wPU17r/AVnM3T+SlDhMwKT7ywathHg0Lo=",
    "IokuyCayBoDIRi7UFuFdQC5Wf/TghLCCdNcC/SQR9Ao=",
    "HYZ+YLZXUR4owVwQCwe2KvN8tCQMZzVMopNzAptVur0=",
    "MOAt5TQAXX8wZOV6x566rUg6373ByyJ7iJ8L1mdRrb4=",
    "ums+ueoM+SR7WW4L+xEpeJBG+lOcBotiVfIZIKFGct4=",
    "lYEiDU1VxiJCBxkiTaTXLtJ8WpCD/MbJdU4LReiSY/8=",
    "0ggqYPbv6LTeNeaVbbR3LMdAB6PBWI1qFHXeXsYHk4g=",
    "YHypZy48RpLglCV84AszKWLuJHVB0Ye2E1SYovYbbVk=",
    "sIZGVn0JxHeTnqf0F/owfsDVIqQdT456q02aiJ7Gf+8=",
    "V18YB4tYdBR+zWYvQmDNs1SHVggew9LnvtI5f2eIhiI=",
    "khPulSUnWR48EP5R3pFsELctkLI0vTZr8tPaicZgZ44=",
    "gOfdPRa1bJA4uafweBmc87p2hB6bgmSsPhA8JNPIhxw=",
    "/Jvwp4z3vBQHreXQeZXOLs4kZ0grxdBPJ77hFuM7Jq0=",
    "DLlKZBGMoQa11it7AyMIVVG3aIq7mfxHrW9Grvea0Oc=",
    "ILVOvzaEVhUBUvIYHlzOf63RjEHNR2QjbGjk/g1J93U=",
    "OY8Mvn+73G5ciPWm5Y2iWWhwXUcE/psWv/e+vzn3g48=",
    "oibe/yL5LplLGBgCbZI7nJOnL41bTyzDz2ItZJI3PbM=",
    "3gVpegdD1RGwBJ5AVadhjO96P1SrLtAx7G0vdcVBatk=",
    "by3Ajkowzox00XW7TY96MviKoUXxkLqGPRRtMEfgHO4=",
    "tyIJC1CSiwex+j1FfP/a9w0E/b8++h1+1AZ9vpJbT3o=",
    "bCeJMLDftI59m9CVwB39Xf+Fl2DLWq//+TmQdnP0REg=",
    "NcbDcJcr8PQuvRI7T9zqqsRVdokDckmz1ktn8DS3R3Q=",
    "Sjbnuu7mYb+eh1DEir2q35aag+Iqkc99KZSWNnyn674=",
    "7iV3kYCcpAl1e8miH4HL2FraA9btu1z0Fxz/LOyH3Xs=",
    "xmAY5gx3TXcMxlOdQsAj+pdMKeP+LbWSXyJrnMXPiwU=",
    "vsPr+6BoNPIkVDzKKkJ8uTKRR76T4ZrrDjOnEZx/Y+8=",
    "D0GiCSG8vDnuOC37VNry2zc85rF4gzER4i9FJmEk88w=",
    "HO+afWaQXiXsF1F9uf/ZHqcfBcEbpm2asR5qRnU+1hc=",
    "mexetYViQceu+/+O+eJF0y+6guWplhBUnEHPJ/OsDVM=",
    "yJtKq/jk0cN8qTL0iN3CgDM0vNzHaVOQCtYwr3BRF2E=",
    "ch8Ok2s7k8A4T5cMB2gKimKT5QEileg2FepGV+1dfhc=",
    "ZE4VIk9VlzUa71xL3SKyfKDBnbIkRDFTTCpKC+v985w=",
    "/e2P2dZVHGAe6zt8a8Xlz9iq0dAVt+mqqcm5R1Ix1eI=",
    "zzzP+SSAopFgwtODF8Qw4UdJv+4XiBBpV9/nP4xJMOU=",
    "zp19yQkT7l2SdFAZR5pTUsbWJ5vvGO0H3AqD7oCE2so=",
    "FJFOMidwaY4JC0RTEGJCQFez3LD736kyKdIXiMqimmw=",
    "0K8HSlGrMTjbBYEXCy9OAvRkCV6a1iy+aKSMaTjzS0c=",
    "OoGkfuJyDxCefRy1Sjb3e2TdRlgD+XFyZKXl8THfXhI=",
    "QTT6Y3zIesUjIPMR9KaB73QLWNqM4sCcch7t1yAXnE8=",
    "SZbTcavVBucheLTL6o6fWteBpaVmVD2X+JpO+xPVu18=",
    "KV/vTUYRDuIfug0XmKG7fBu8iDBrybdmGxis5xcPAq4=",
    "oyrrcozVAGn5BlWRWPHQqd86jGeV5cuv3gDGMvCLreM=",
    "k2VzQrtJvJ4kLE9Vc+9iHWzZD0oggrFP74W8mITQCsk=",
    "NEYuG0ciabwnCm2/CdkHX+nLU1DMS3Q4DResGdWA0SU=",
    "wbu8guhRK7vfvLnZpoVSvU7zt5U1QUUcgvO8kqyMS/k=",
    "liz4EH3zhbThsbP+NpS7xzHSH6qvvCtI6hUEzgfxkXM=",
    "B4dI3eX+OM+K9IJgy1Mb+O9o8nAEN8HbPiEN7LdXQXs=",
    "raojyh7Ykq0c8CjNQLqK4r/T198SicPyMZByEG9Yepg=",
    "7GVs3mq8gajIXF9oLTknN8SV3IcTA9w9EfxlF2Wtmbw=",
    "vHRON0/YPN9u3XCWicTzvN5WumEkafMxeJrE5zj4BLQ=",
    "TNmlDj9CemTjEqGs2Lw51HAw7h6sFz6Ex1xIHTzxORE=",
    "71qYDnbpLJS8Q8XbNK4luZCxuKTMKOg060ykondX/m8=",
    "pZUmrheKqjzT0YSfmu65FPxVXKeQwY7B6mOBTkVIAYk=",
    "kpFbMHjaLsMZeBI2kVF4Na9H7sEtkWLSaZANDdoOxY4=",
    "gbcHbT7EiTk6F1L0tyxRycrQveDyrsb0AnOenCA1lnQ=",
    "O8zVQ5/HxL0wJWdfepw5/4fIz9vq2gtt0p6xeWKaaJw=",
    "dkv3Itr3Lo8EroMLEDE8g2ZnZ23Z6KBy5KHASC6mgvQ=",
    "O97kbmA7xApxnoSpkTRo15DuMxVxlSF8GnI1lqlwips=",
    "5Vqq9vUdQ6Uza6TSmvISjD3DvD2dcLPkGVD0Rb6x5ak=",
    "8HG+CRhOSEntSPP3HLJUqdeSwaN7qPYRGb5K5fXF6b4=",
    "ufblP/mJLbCgSAUnDl1gs8YvcrzM8gUsuroq4stzLHg=",
    "V26d1PfOTpQy1FbQLFq3fhWh2/dOYPRjL4AGGnVrwgE=",
    "Z9EaN0kUISJMHtZLPSr5w7RcQT+g++2w7RvtJhJnA90=",
    "T+55aOaLHcdcFOI8FsTN25+6EK5+2u8yNF19lFDwXNg=",
    "ysVFjUjmFjzIQ9XxjiY+POAykMvVqGa9O30C3/LaQT4=",
    "Npozut+mGNWNFqrd6v+Y1mswpwwt7uQvyAm5ch3BxSQ=",
    "bZ7yK4cfhRjZH+X9SLr1FPEWXsoKFF+JdetLQImNq3w=",
    "kuRySKlZH3fTkGc1m5H7oPAR8cdT6ShMULoQ+kNsreE=",
    "mKxAnC6fotqoGjbr0YjOugsZl/nId2xzrzYKXJ1ridc=",
    "qTF5dek1oTyOhuXC29nIKZNqeiIqKLUtZgfpn6o2KqQ=",
    "uMjVO8zx8bZdyo9wGFPm+1daCSnJ3XwLzcM4HsTovIA=",
    "jrn4PbzbnLn++qcT6mvTADib1fhftjrrYLvznwByoRU=",
    "yRNDTGJfubmWns3V/GIrUxUrgS9gXBJ0p1VO4YvCa70=",
    "KjwFCA6QTqywJXdNVtYMROdxa5DtcF2GQJdaHHUtbqw=",
    "1MGdfs1iwpj8b8+0JW7XII1MuwH4HKHB98NsmlVmf4A=",
    "u1+VEyvsfE2nK8OMIhy4vkWPkCM896XaRwqJqv+AV70=",
    "h/bznMP8okznFEDPTveSyPyg1yKRBEhJola8e/elmVA=",
    "4FqjKJd06ck0uktqYhoWAryNUtKqqIQRqt+sNuJZ3t8=",
    "oQS2DKjnsJqkshYlpv/NYFYIiXNqNo3tH0uo6tjucyo=",
    "B/A8sGFUefqWRjLoShKnqv3ysLbnbJqh+ryusP2J/OA=",
    "dYBlWgRFZpAwzOwTPLc+g6YouOH1DDuTPIiefLP4Oqc=",
    "oMAWnqIny8Z9jllCEYtKOntGVGaOhvTDMgEwZ90PIBQ=",
    "M71XAQaSEoFIti4hoaQ1CX8BvdIXOeEjHW55sieugoc=",
    "TFpCWt9uws9bULRD4BTZBDZZME2lELuEH9AU8E+5Vb8=",
    "Gv8gOc1nDvLtB+aYWM3jm8sIkKmHJdH7LR38TNLcVFo=",
    "owB/IVXitzFLNoXoSPJJzz8y8X4MrnNvhRXx7oRosGs=",
    "1FafM1bItCZCGy8V9tzhTEBiFqHN8qrnjpmudlAD1Tw=",
    "aaqTePChfguIz4UXGvIvVpwyH2bK8xk8jeEwsAesVh4=",
    "hlgXMyG44aHbbFUZKFHLaBsX8LibENTVdmrA7+OJ22I=",
    "uGv76n4/jQqiOh0fbjjemMChBGJ0ZkrRhjzy/5p/lWU=",
    "lhRQ51MTU3+iOw4+oQojHM4N8+0uX/TvD3PCZ3bP17Q=",
    "xyIgZyNlUUuNc42YSaApu/CxTE0Y56OyeqfpCl2gFeM=",
    "lHob1hCmxU198WbsI17MOmhqCrgUPsSb6nVPEsA0Ycg=",
    "n0DCM8LYaJJv+QFoINteYkQCixoEGmK64QWv/IWmQ8Y=",
    "MHJu/PwCrd0PgSMAvjOtxtZN9HrqIMCqCRl6gN2yTc0=",
    "48tZpBbOs4Ee8Xl41ltXwWcF8gXSG9t/W5WOsJ0ht1g=",
    "8bS8UWiRw/pE8QcK3AXhFkCA+6P3oXhAwlseNYTBFUA=",
    "X3KPY79e5Ix39FPASQOY+mRbjUxOVr6aQc/sNE1sqJk=",
    "DiQTEkW2rmNKvExH3J+z6bl5Zgd/cxHFzmsm4EnmjUA=",
    "P5lLzDBX7ymYJ9bPpHSC8XssrcRFJNVhSlvhfWHU51E=",
    "EojcqPKM+/gRaV68ONloTqAMXxOTelJ8Q8qsPAvSneo=",
    "It5z/4Ur5jMt0QN/AHWLl1tMtnEdUVJI3Os5Y3OF1Eo=",
    "OXysyvP4fzh8/tRgKCr8DSSrWlmY6v2T4f+YS+0AeEA=",
    "Y+jvk0GBsU6i9sJKkr5NZeOU9RJ2aITTf8ue8LOYQOE=",
    "OemZ5w35Qx2oYyXbGSkWorGPv1Lc9iAmMQyQPKzv3So=",
    "gd0RZXjQ9OIekpZYPIFsO04l687qtb0d5uNJPkCa21A=",
    "nin5ZFP0dNKBHXgKtD/3TC12jvidzI598Fv6wdnHVfE=",
    "bk57foGXk6PeF/o9ScV1ThVDb6r0PmRyJhtn/En1eUI=",
    "ovhv+Z2qW8rckhfAmV/m4Gzj5NZ+Gt1bzpY3iLmBPsA=",
    "/t5/+KXE1+3D2zoguVrvci6RbWf2S6+Jp8d0+/CAR0s=",
    "QcBcexJ3wXyfbo8sjMujYWZ3Dblw3AT4SoUlsYi1/+Q=",
    "Tfyy+rUxS8BsLkHYN+u0d3+GG+KV/O1DRVLhLdqtK7w=",
    "B4/Pw6KSB6tPJRyUcF7b0BQ+j/G51eaVNbgJcctAmCY=",
    "NO7qmxmHpYAAMynMhsQLzl2VhGzdbuhOajWrogcCt84=",
    "BW0h1viVubqb8WJT60BSS2bnYXZ8ZfQbKZT3AmKE8nM=",
    "M9CkvU2hm7xJwGRoDosiTDtaldk8uDHmWSyPcAxp3lg=",
    "o7jVXqG9+MT6TSJZODbe7Gb5Y3rJto/vlFcPIyCXBoA=",
    "h8xEM//I58/gdXzIDak/oop4OVyM4oOHRpX0zHuh8Ts=",
    "mdXDmmD5TEKJQsBQ8CW2cGRAsaBE2FLnM/94OsODN7E=",
    "zeSh0oFkFZYyJDvIlvKTJHabqkowOjgfAbzNc/BWVN0=",
    "8bdAtcDrtlfgtqKKx/Zp7YOXw0CqE7JdvVyYuBE6gw4=",
    "tzW1zpqBRGrt/TE+SS58EbkecYiMWlKWKtq82deQXHM=",
    "5E+rsKcQ+QfJQPh5h/RmQag8VpPu8dnOfYLmcIs+OZQ=",
    "HVFa7Fw4FvMkPN1W9e1RpwaSwI92czkU8kNESH6EsZU=",
    "8XabXTnwekq6gy9bL4Rb3Io5pKziez6aT4Q8gTO3heA=",
    "4V7j2fFpzElez0DaWXgLhmLncxEa3Ou5yB8GABw3eug=",
    "E/zh/RC5KWsx8E6asVPBC2wldfu4FGBdGLnDLpzkowY=",
    "dtTqgXcu3g2hkRVPIfC4m4iR8jR+2MONg7X7gsWdc7o=",
    "pZIiilb4WPRiJD1tY8FvFOhjOTycsfNWnnwHAzEpdG8=",
    "fHi9nkGEQ3WEhWbCQBQ6q1fY5nNRFQRi6jZwexdyudk=",
    "0O/wFYUnRqwDpEXqidj2IFePTYwgzQo3bFKSyNs5nmg=",
    "uv/5h/FSFUkP4JOU7e48yiGWSVaKzVCB5b2tqYBTQTY=",
    "CvWmTeT74JPBY8IPIlVKQTULhhM+HoaSOd/ijL7ozkI=",
    "ma+Df8/wU+LhpAYRP4fEl11kkNVXzzmRoTwoi75OR2o=",
    "vBHViPGUStz2tzymUMvMDiOoKAICbjojwhfawdsjAOA=",
    "jVqcv3P1FlivWI/DoJ1eUclFuwHCaaNg3rUG2WW3TdY=",
    "ZkJM2JceQ/L0ehZmVO0/YBr3ZBUfaaH4DnXZzyqUyLg=",
    "bG9UkpnGnsSGgca5aI5K7AIuFvcNunBdVieJ0EXLcWM=",
    "XzfSlS7B+YBMJxIwdeYb9rwACy4BaVLO1PffbuFAZZY=",
    "cMnpaeiF1lu0wpyZJc2Mzk6bTD3qgfjtiK+YcJATAAI=",
    "VYqHDMSloXsDE4BMfGaRoxi6Km1U7zSAC/e1DJDuOsc=",
    "2ECQogK1MTF8FHbqTMgkEG1jW0vUH7wIGw2UJSXfcz4=",
    "Enp0qEmjkNj/YAUXCtvMVnNzTPyidu7VRow0NtHk6Vc=",
    "UTaNHr7d/oqQBaXZYnvC//XvEA0o4kbutq6m+TAn5F8=",
    "Dtkb4xlGTqUMlAUQWnU2cYITTnrD0uXjBUUzdrq+6Rk=",
    "PUvCv16MtbcAmHFO4J4WupvhJd9wLQ5bgNAnswmJoVQ=",
    "LyOFKPMDNtAOpJM1KIYmVFScgAQnxDrrt0Z17ugntfU=",
    "xcUvWy613eycN8iSLeTuj/qLZ0hwkXwg5Ohi34zQkKk=",
    "jJT27NPjNDPQTmNKJsTO0RhLm8avR1YsRFkwlJSp9XQ=",
    "0wNvCZQUqRh7edOu0vVP0GjrL6sjIqecDUa4qMt3fi4=",
    "JQdFBzHBFkTy3iO5cgvNcagncl+PsRpiIZTru+FiM78=",
    "brvFTqwulQblprNeCciZpoeKy9P3+c7mApgvR597zmY=",
    "zrlOLovUW7tK8qOqoFzD97wBCmxo4kKSPONzGhCN+OE="
];

// Test input is [ 0, 1, 2, ..., 255 ].
const input = new Uint8Array(256);
for (let i = 0; i < input.length; i++) {
    input[i] = i & 0xff;
}

describe("sha3.SHA3(256)", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new SHA3(32);
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors256[i]);
        }
    });

    it("should correctly update multiple times", () => {
        const h1 = new SHA3(32);
        h1.update(input.subarray(0, 1));
        h1.update(input.subarray(1, 120));
        h1.update(input.subarray(120, 256));
        const h2 = new SHA3(32);
        h2.update(input.subarray(0, 256));
        expect(encode(h1.digest())).toBe(encode(h2.digest()));
    });

    it("should return the same digest after finalizing", () => {
        let h = new SHA3(32);
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new SHA3(32);
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new SHA3(32);
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 32-byte digest", () => {
        let h = new SHA3(32);
        h.update(input);
        expect(h.digest().length).toBe(32);
    });

    it("should correctly hash 3 GiB", () => {
       const h = new SHA3256();
       const buf = new Uint8Array(256 * 1024 * 1024); // 256 MiB
       for (let i = 0; i < buf.length; i++) {
           buf[i] = i & 0xff;
       }
       for (let i = 0; i < 12; i++) { // 3 GiB
           buf[0] = i & 0xff;
           h.update(buf);
       }
       expect(encode(h.digest())).toBe("Io2epOVFOlkNVxoMbyHIvQUYxRnZ1ep3qr2GEXe7WV8=");
    });

});

describe("SHAKE128", () => {
    it("should produce correct output for test vectors", () => {
        const good = "s5tY1Mbc7McVl7F59PVSL/+XKcmtCaQXxBR9ASJfsN0=";
        const total = new SHA3256();
        for (let i = 0; i < input.length; i++) {
            const h = new SHAKE128();
            h.update(input.subarray(0, i));
            const buf1 = new Uint8Array(i);
            h.stream(buf1);
            total.update(buf1);
            const buf2 = new Uint8Array(17);
            h.stream(buf2);
            total.update(buf2);
        }
        expect(encode(total.digest())).toBe(good);
    });
});

describe("SHAKE256", () => {
    it("should produce correct output for test vectors", () => {
        const good = "zoCF2ar8O8pLdLNfNBkOtGkjDMh8iweudQS8hXYyZr0=";
        const total = new SHA3256();
        for (let i = 0; i < input.length; i++) {
            const h = new SHAKE256();
            h.update(input.subarray(0, i));
            const buf1 = new Uint8Array(i);
            h.stream(buf1);
            total.update(buf1);
            const buf2 = new Uint8Array(17);
            h.stream(buf2);
            total.update(buf2);
        }
        expect(encode(total.digest())).toBe(good);
    });
});
