# WF-SECRETS-SCOPE snapshot review

Baseline: original WF commit `874f804` (the supplied patch on `bcd3850`). Only inert, seeded CI corpora were read. Case IDs below are zero-based output indices from `scripts/snapshot.py`.

Every changed output is classified below. For every pair, the review asserts that all non-bulk findings, hardening findings, other fields, and issue records are identical. No unrelated output changed.

## ci-exfil

1461 of 6000 outputs changed.

| Source transition | Count |
|---|---:|
| a network command → cannot clear a listening socket | 5 |
| a network command → cannot clear an opaque or unsupported sender | 25 |
| a network command → cannot clear an unmodeled data or file hand-off | 23 |
| a network command → held | 63 |
| held → a network command | 232 |
| held → cannot clear a listening socket | 18 |
| held → cannot clear an opaque or unsupported sender | 99 |
| held → cannot clear an unmodeled data or file hand-off | 160 |

Case groups (a case with multiple sources can have several transitions):

- **a network command → cannot clear a listening socket**: 790, 1632, 3104, 4716.
- **a network command → cannot clear a listening socket; a network command → cannot clear an unmodeled data or file hand-off**: 3664.
- **a network command → cannot clear an opaque or unsupported sender**: 234, 290, 404, 868, 1600, 1744, 2076, 2262, 2700, 3232, 3390, 3560, 3638, 3650, 3734, 4548, 4628, 5362, 5624, 5866, 5982.
- **a network command → cannot clear an opaque or unsupported sender; a network command → cannot clear an unmodeled data or file hand-off**: 762.
- **a network command → cannot clear an opaque or unsupported sender; a network command → held**: 2210.
- **a network command → cannot clear an unmodeled data or file hand-off**: 988, 1148, 1166, 1180, 1828, 1930, 2692, 3308, 3880, 3964, 4254, 4360, 4544, 4642, 5188.
- **a network command → cannot clear an unmodeled data or file hand-off; a network command → held**: 1416, 2968, 3498, 4754, 5126.
- **a network command → held**: 692, 846, 982, 1108, 1184, 1216, 1240, 1242, 1258, 1336, 1356, 1690, 1812, 1842, 1850, 1962, 2060, 2120, 2216, 2266, 2426, 2444, 2540, 3098, 3144, 3202, 3212, 3294, 3410, 3510, 3678, 3756, 3830, 3894, 3966, 4112, 4216, 4366, 4488, 4528, 4660, 4802, 5216, 5268, 5276, 5330, 5386, 5674, 5706, 5768, 5804, 5806, 5834, 5920, 5952.
- **held → a network command**: 108, 200, 246, 282, 286, 378, 442, 480, 486, 514, 526, 530, 540, 600, 642, 658, 736, 738, 752, 768, 776, 806, 842, 844, 860, 878, 886, 888, 930, 942, 970, 980, 1040, 1044, 1048, 1084, 1132, 1160, 1290, 1322, 1324, 1382, 1396, 1430, 1468, 1474, 1508, 1636, 1650, 1666, 1684, 1712, 1714, 1720, 1728, 1738, 1742, 1800, 1926, 1934, 1990, 2010, 2022, 2036, 2056, 2080, 2082, 2108, 2128, 2146, 2156, 2180, 2194, 2202, 2258, 2260, 2272, 2400, 2402, 2422, 2468, 2476, 2532, 2638, 2694, 2810, 2836, 2850, 2870, 2886, 2908, 2954, 2962, 2980, 2996, 2998, 3016, 3048, 3136, 3142, 3168, 3186, 3200, 3264, 3284, 3296, 3346, 3364, 3378, 3426, 3430, 3444, 3486, 3540, 3552, 3610, 3614, 3620, 3630, 3694, 3726, 3732, 3744, 3794, 3834, 3846, 3862, 3870, 3922, 3930, 3956, 3976, 3998, 4002, 4010, 4056, 4070, 4074, 4078, 4108, 4136, 4140, 4150, 4162, 4172, 4194, 4200, 4204, 4210, 4264, 4272, 4374, 4426, 4430, 4468, 4512, 4518, 4524, 4530, 4554, 4594, 4640, 4652, 4666, 4684, 4704, 4738, 4772, 4776, 4840, 4866, 4938, 5044, 5062, 5068, 5072, 5082, 5084, 5132, 5136, 5156, 5178, 5270, 5294, 5416, 5456, 5466, 5738, 5742, 5788, 5808, 5874, 5896, 5926, 5978.
- **held → a network command; held → cannot clear a listening socket**: 62, 5366.
- **held → a network command; held → cannot clear an opaque or unsupported sender**: 12, 114, 344, 916, 1116, 2026, 2964, 3462, 4370, 5064, 5924.
- **held → a network command; held → cannot clear an unmodeled data or file hand-off**: 126, 542, 638, 872, 1448, 2098, 2104, 3690, 4692, 5016, 5088, 5242.
- **held → cannot clear a listening socket**: 538, 634, 758, 1368, 2284, 2508, 3010, 3174, 3472, 3724, 3806, 5032, 5368, 5872.
- **held → cannot clear a listening socket; held → cannot clear an opaque or unsupported sender**: 4146.
- **held → cannot clear a listening socket; held → cannot clear an unmodeled data or file hand-off**: 3388.
- **held → cannot clear an opaque or unsupported sender**: 32, 92, 142, 230, 312, 316, 376, 662, 824, 1156, 1170, 1192, 1284, 1286, 1306, 1312, 1328, 1332, 1458, 1580, 1582, 1596, 1630, 1640, 1724, 1834, 1918, 2094, 2130, 2206, 2248, 2282, 2320, 2384, 2410, 2418, 2458, 2550, 2680, 2736, 2772, 2774, 2780, 2804, 2948, 3058, 3224, 3270, 3302, 3688, 3752, 3904, 3910, 3934, 4106, 4218, 4278, 4306, 4324, 4382, 4386, 4818, 5104, 5168, 5220, 5332, 5336, 5408, 5446, 5544, 5686, 5700, 5722, 5746, 5800, 5856, 5882, 5928, 5970, 5994.
- **held → cannot clear an opaque or unsupported sender; held → cannot clear an unmodeled data or file hand-off**: 2742, 3020, 4380, 4906.
- **held → cannot clear an unmodeled data or file hand-off**: 58, 70, 196, 228, 232, 284, 322, 348, 386, 426, 574, 578, 652, 656, 666, 714, 728, 750, 774, 1012, 1064, 1208, 1274, 1288, 1292, 1308, 1358, 1372, 1426, 1456, 1490, 1794, 1844, 1892, 1898, 1902, 1922, 1942, 2014, 2096, 2114, 2152, 2220, 2234, 2268, 2316, 2330, 2412, 2414, 2488, 2580, 2702, 2712, 2776, 2788, 2826, 2830, 2914, 2940, 2942, 2978, 3030, 3056, 3068, 3078, 3112, 3132, 3258, 3338, 3348, 3508, 3514, 3566, 3590, 3592, 3594, 3682, 3686, 3710, 3740, 3810, 3944, 4018, 4030, 4054, 4094, 4124, 4170, 4208, 4240, 4290, 4316, 4338, 4376, 4378, 4410, 4458, 4460, 4472, 4500, 4550, 4580, 4654, 4658, 4762, 4798, 4832, 4882, 4900, 5058, 5160, 5252, 5288, 5290, 5292, 5314, 5324, 5352, 5554, 5568, 5704, 5732, 5744, 5770, 5784, 5840, 5858, 5894, 5972, 5986.
- **issue CRITICAL → MAJOR; issue wording only**: 693, 847, 983, 1109, 1185, 1217, 1241, 1243, 1259, 1337, 1357, 1417, 1691, 1813, 1843, 1851, 1963, 2061, 2121, 2211, 2217, 2267, 2427, 2445, 2541, 2969, 3099, 3145, 3203, 3213, 3295, 3411, 3499, 3511, 3679, 3757, 3831, 3895, 3967, 4113, 4217, 4367, 4489, 4529, 4661, 4755, 4803, 5127, 5217, 5269, 5277, 5331, 5387, 5675, 5707, 5769, 5805, 5807, 5835, 5921, 5953.
- **issue MAJOR → CRITICAL**: 13, 33, 59, 63, 71, 93, 109, 115, 127, 143, 197, 201, 229, 231, 233, 247, 283, 285, 287, 313, 317, 323, 345, 349, 377, 379, 387, 427, 443, 481, 487, 515, 527, 531, 539, 541, 543, 575, 579, 601, 635, 639, 643, 653, 657, 659, 663, 667, 715, 729, 737, 739, 751, 753, 759, 769, 775, 777, 807, 825, 843, 845, 861, 873, 879, 887, 889, 917, 931, 943, 971, 981, 1013, 1041, 1045, 1049, 1065, 1085, 1117, 1133, 1157, 1161, 1171, 1193, 1209, 1275, 1285, 1287, 1289, 1291, 1293, 1307, 1309, 1313, 1323, 1325, 1329, 1333, 1359, 1369, 1373, 1383, 1397, 1427, 1431, 1449, 1457, 1459, 1469, 1475, 1491, 1509, 1581, 1583, 1597, 1631, 1637, 1641, 1651, 1667, 1685, 1713, 1715, 1721, 1725, 1729, 1739, 1743, 1795, 1801, 1835, 1845, 1893, 1899, 1903, 1919, 1923, 1927, 1935, 1943, 1991, 2011, 2015, 2023, 2027, 2037, 2057, 2081, 2083, 2095, 2097, 2099, 2105, 2109, 2115, 2129, 2131, 2147, 2153, 2157, 2181, 2195, 2203, 2207, 2221, 2235, 2249, 2259, 2261, 2269, 2273, 2283, 2285, 2317, 2321, 2331, 2385, 2401, 2403, 2411, 2413, 2415, 2419, 2423, 2459, 2469, 2477, 2489, 2509, 2533, 2551, 2581, 2639, 2681, 2695, 2703, 2713, 2737, 2743, 2773, 2775, 2777, 2781, 2789, 2805, 2811, 2827, 2831, 2837, 2851, 2871, 2887, 2909, 2915, 2941, 2943, 2949, 2955, 2963, 2965, 2979, 2981, 2997, 2999, 3011, 3017, 3021, 3031, 3049, 3057, 3059, 3069, 3079, 3113, 3133, 3137, 3143, 3169, 3175, 3187, 3201, 3225, 3259, 3265, 3271, 3285, 3297, 3303, 3339, 3347, 3349, 3365, 3379, 3389, 3427, 3431, 3445, 3463, 3473, 3487, 3509, 3515, 3541, 3553, 3567, 3591, 3593, 3595, 3611, 3615, 3621, 3631, 3683, 3687, 3689, 3691, 3695, 3711, 3725, 3727, 3733, 3741, 3745, 3753, 3795, 3807, 3811, 3835, 3847, 3863, 3871, 3905, 3911, 3923, 3931, 3935, 3945, 3957, 3977, 3999, 4003, 4011, 4019, 4031, 4055, 4057, 4071, 4075, 4079, 4095, 4107, 4109, 4125, 4137, 4141, 4147, 4151, 4163, 4171, 4173, 4195, 4201, 4205, 4209, 4211, 4219, 4241, 4265, 4273, 4279, 4291, 4307, 4317, 4325, 4339, 4371, 4375, 4377, 4379, 4381, 4383, 4387, 4411, 4427, 4431, 4459, 4461, 4469, 4473, 4501, 4513, 4519, 4525, 4531, 4551, 4555, 4581, 4595, 4641, 4653, 4655, 4659, 4667, 4685, 4693, 4705, 4739, 4763, 4773, 4777, 4799, 4819, 4833, 4841, 4867, 4883, 4901, 4907, 4939, 5017, 5033, 5045, 5059, 5063, 5065, 5069, 5073, 5083, 5085, 5089, 5105, 5133, 5137, 5157, 5161, 5169, 5179, 5221, 5243, 5253, 5271, 5289, 5291, 5293, 5295, 5315, 5325, 5333, 5337, 5353, 5367, 5369, 5409, 5417, 5447, 5457, 5467, 5545, 5555, 5569, 5687, 5701, 5705, 5723, 5733, 5739, 5743, 5745, 5747, 5771, 5785, 5789, 5801, 5809, 5841, 5857, 5859, 5873, 5875, 5883, 5895, 5897, 5925, 5927, 5929, 5971, 5973, 5979, 5987, 5995.
- **issue wording only**: 25, 31, 77, 79, 83, 85, 91, 113, 125, 137, 187, 189, 207, 223, 235, 239, 245, 253, 255, 277, 281, 291, 331, 341, 351, 361, 399, 405, 415, 423, 429, 445, 451, 461, 467, 469, 485, 493, 497, 535, 577, 599, 605, 611, 649, 671, 673, 685, 691, 733, 735, 745, 757, 763, 791, 793, 803, 815, 827, 853, 869, 891, 895, 915, 967, 973, 975, 989, 995, 1005, 1011, 1015, 1019, 1025, 1027, 1053, 1055, 1073, 1107, 1119, 1135, 1137, 1149, 1159, 1165, 1167, 1181, 1215, 1237, 1253, 1295, 1303, 1341, 1345, 1355, 1361, 1367, 1381, 1399, 1401, 1413, 1425, 1489, 1517, 1521, 1531, 1539, 1575, 1601, 1633, 1639, 1645, 1647, 1649, 1657, 1661, 1701, 1703, 1709, 1719, 1723, 1727, 1731, 1745, 1747, 1759, 1791, 1797, 1829, 1831, 1871, 1889, 1891, 1905, 1911, 1913, 1931, 2009, 2013, 2033, 2045, 2047, 2071, 2077, 2087, 2091, 2103, 2137, 2165, 2193, 2201, 2237, 2239, 2251, 2253, 2263, 2265, 2309, 2313, 2315, 2337, 2339, 2359, 2365, 2369, 2389, 2421, 2453, 2457, 2465, 2483, 2499, 2511, 2559, 2575, 2587, 2595, 2599, 2603, 2607, 2641, 2661, 2693, 2701, 2705, 2747, 2757, 2787, 2795, 2823, 2847, 2857, 2873, 2875, 2889, 2897, 2899, 2911, 2913, 2917, 3045, 3065, 3087, 3089, 3091, 3103, 3105, 3117, 3121, 3131, 3147, 3161, 3171, 3197, 3215, 3221, 3229, 3233, 3257, 3269, 3283, 3309, 3323, 3325, 3341, 3361, 3381, 3391, 3399, 3401, 3409, 3425, 3433, 3447, 3451, 3479, 3485, 3507, 3519, 3523, 3561, 3575, 3597, 3629, 3635, 3639, 3649, 3651, 3665, 3677, 3681, 3735, 3759, 3775, 3781, 3793, 3801, 3809, 3825, 3855, 3869, 3873, 3881, 3909, 3913, 3951, 3965, 3985, 3997, 4023, 4059, 4065, 4073, 4089, 4091, 4093, 4119, 4121, 4145, 4165, 4185, 4193, 4197, 4223, 4227, 4229, 4237, 4243, 4255, 4257, 4275, 4301, 4309, 4337, 4343, 4349, 4361, 4395, 4397, 4419, 4435, 4441, 4445, 4449, 4467, 4477, 4493, 4495, 4507, 4517, 4541, 4545, 4549, 4567, 4593, 4629, 4643, 4657, 4679, 4683, 4687, 4689, 4701, 4713, 4717, 4719, 4727, 4753, 4787, 4825, 4829, 4859, 4863, 4871, 4881, 4897, 4905, 4925, 4943, 4961, 4975, 4991, 5009, 5011, 5013, 5043, 5047, 5055, 5067, 5075, 5101, 5115, 5143, 5149, 5167, 5177, 5189, 5205, 5213, 5259, 5261, 5311, 5345, 5361, 5363, 5377, 5381, 5383, 5421, 5433, 5453, 5459, 5501, 5531, 5539, 5541, 5561, 5563, 5571, 5625, 5631, 5641, 5647, 5761, 5777, 5795, 5829, 5837, 5847, 5863, 5867, 5869, 5901, 5961, 5983, 5989, 5993.

## ci-workflow

4 of 15693 outputs changed.

| Source transition | Count |
|---|---:|
| held → an artifact upload | 2 |

Case groups (a case with multiple sources can have several transitions):

- **held → an artifact upload**: 3615, 5934.
- **issue MAJOR → CRITICAL**: 3617, 5936.

## Why these changes are expected

- Held → network: full-object sends no longer disappear behind credential, loopback, secret-host/path or sweep exemptions. Piped input retains its source.
- Held → artifact: missing paths mean workspace and a written secret file is covered; the two workflow cases are #3615 and #5934, with their issue twins #3617 and #5936.
- Held → cannot clear: opaque or unsupported sender options retain CRITICAL when bulk secrets are reachable. Listening sockets receiving bulk input are also uncleared.
- Network → held: the old global promotion is removed. These sources were overwritten, only stored/assigned, belonged to unrelated jobs or steps, or were not the source used by a send. Comments mentioning the source also do not become proof of a send.
- Network → cannot clear: the source cannot be positively cleared, but its own send is not proven. The old reason was borrowed from another source.
- Issue wording only: proven sends now say that the value is sent; uncertainty explicitly says the reader cannot rule out exposure. The shared explanation describes positive clearance. No named-secret issue or other rule changes.

The original reviewer probe programs were not attached. The 130 package regression cases are independent reconstructions and additions. Real-workflow, popular-set, malware and holdout measurements remain owed by John.

## Validation environment and gates

- Linux x86_64; Rust 1.99.1, Python 3.12.14, Node 24.19.0. Node 22 and macOS were not run here.
- All 457 Rust engine tests passed on the final optimized build (4.12 seconds).
- 130 inert scope cases in each package, plus existing persistence and named-secret tests.
- All 88 npm test modules passed; the affected persistence, exfiltration and hardening modules were rerun on the final WASM.
- 32 distinct Python modules passed, including all 19 snapshot modules, workflow/hook wiring, suppression integrity, dashboard, CLI parity and native/WASM CI parity. Affected modules were rerun on the final native library.
- CI parity now includes the 6,000-call exfiltration corpus as well as workflows, outlines, GitLab and helpers.
- The 8,000-job timing regression was fixed by indexing job records once and sharing source maps. The 60-test hardening module passes its existing bounds.
- Canonical pack, synchronized 2.89.0 rule-set assertions, generated-table check, WASM packaging check, dashboard generation/check and whitespace checks pass.
- Test modules run separately under 45-second timeouts for the final gates.

The RA-6 deletion-detection item is not part of this commit. Its supplied handoff assumes a later rebuilt stack through TS-STRIP (2.93.0) and additional Python changes, and requires confirming which commits are applied before choosing the next rule set. This checkout does not contain that stack; its base must be confirmed with John.
