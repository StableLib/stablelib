// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { benchmark, report } from "@stablelib/benchmark";
import { mul, div } from "./gf256.js";

report("gf256.mul", benchmark(() => mul(100, 18)));
report("gf256.div", benchmark(() => div(100, 18)));
