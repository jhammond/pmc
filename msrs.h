#ifndef _MSRS_H_
#define _MSRS_H_
#define AMD_PERF_CTL0     0xC0010000
#define AMD_PERF_CTL1     0xC0010001
#define AMD_PERF_CTL2     0xC0010002
#define AMD_PERF_CTL3     0xC0010004
#define AMD_PERF_CTR0     0xC0010004
#define AMD_PERF_CTR1     0xC0010005
#define AMD_PERF_CTR2     0xC0010006
#define AMD_PERF_CTR3     0xC0010007
#define AMD_EXT_PERF_CTL0 0xC0010200
#define AMD_EXT_PERF_CTL1 0xC0010202
#define AMD_EXT_PERF_CTL2 0xC0010204
#define AMD_EXT_PERF_CTL3 0xC0010206
#define AMD_EXT_PERF_CTL4 0xC0010208
#define AMD_EXT_PERF_CTL5 0xC001020A
#define AMD_EXT_PERF_CTR0 0xC0010201
#define AMD_EXT_PERF_CTR1 0xC0010203
#define AMD_EXT_PERF_CTR2 0xC0010205
#define AMD_EXT_PERF_CTR3 0xC0010207
#define AMD_EXT_PERF_CTR4 0xC0010209
#define AMD_EXT_PERF_CTR5 0xC001020B
#define AMD_NB_PERF_CTL0  0xC0010240
#define AMD_NB_PERF_CTL1  0xC0010242
#define AMD_NB_PERF_CTL2  0xC0010244
#define AMD_NB_PERF_CTL3  0xC0010246
#define AMD_NB_PERF_CTR0  0xC0010241
#define AMD_NB_PERF_CTR1  0xC0010243
#define AMD_NB_PERF_CTR2  0xC0010245
#define AMD_NB_PERF_CTR3  0xC0010247
#define IA32_PMC0                        0x0C1
#define IA32_PMC1                        0x0C2
#define IA32_PMC2                        0x0C3
#define IA32_PMC3                        0x0C4
#define IA32_PMC4                        0x0C5
#define IA32_PMC5                        0x0C6
#define IA32_PMC6                        0x0C7
#define IA32_PMC7                        0x0C8
#define IA32_PERFEVTSEL0                 0x186
#define IA32_PERFEVTSEL1                 0x187
#define IA32_PERFEVTSEL2                 0x188
#define IA32_PERFEVTSEL3                 0x189
#define IA32_PERFEVTSEL4                 0x18A
#define IA32_PERFEVTSEL5                 0x18B
#define IA32_PERFEVTSEL6                 0x18C
#define IA32_PERFEVTSEL7                 0x18D
#define IA32_OFFCORE_RSP0                0x1A6
#define IA32_OFFCORE_RSP1                0x1A7
#define IA32_FIXED_CTR0                  0x309 /* Instr_Retired.Any, CPUID.0AH: EDX[4:0] > 0 */
#define IA32_FIXED_CTR1                  0x30A /* CPU_CLK_Unhalted.Core, CPUID.0AH: EDX[4:0] > 1 */
#define IA32_FIXED_CTR2                  0x30B /* CPU_CLK_Unhalted.Ref, CPUID.0AH: EDX[4:0] > 2 */
#define IA32_FIXED_CTR_CTRL              0x38D /* CPUID.0AH: EAX[7:0] > 1 */
#define IA32_PERF_GLOBAL_STATUS          0x38E
#define IA32_PERF_GLOBAL_CTRL            0x38F
#define IA32_PERF_GLOBAL_OVF_CTRL        0x390
#define IA32_UNCORE_PERF_GLOBAL_CTRL     0x391
#define IA32_UNCORE_PERF_GLOBAL_STATUS   0x392 /* Overflow bits for PC{0..7}, FC0, PMI, CHG. */
#define IA32_UNCORE_PERF_GLOBAL_OVF_CTRL 0x393 /* Write to clear status bits. */
#define IA32_UNCORE_FIXED_CTR0           0x394 /* Uncore clock. */
#define IA32_UNCORE_FIXED_CTR_CTRL       0x395
#define IA32_UNCORE_ADDR_OPCODE_MATCH    0x396
#define IA32_UNCORE_PMC0                 0x3B0
#define IA32_UNCORE_PMC1                 0x3B1
#define IA32_UNCORE_PMC2                 0x3B2
#define IA32_UNCORE_PMC3                 0x3B3
#define IA32_UNCORE_PMC4                 0x3B4
#define IA32_UNCORE_PMC5                 0x3B5
#define IA32_UNCORE_PMC6                 0x3B6
#define IA32_UNCORE_PMC7                 0x3B7
#define IA32_UNCORE_PERFEVTSEL0          0x3C0
#define IA32_UNCORE_PERFEVTSEL1          0x3C1
#define IA32_UNCORE_PERFEVTSEL2          0x3C2
#define IA32_UNCORE_PERFEVTSEL3          0x3C3
#define IA32_UNCORE_PERFEVTSEL4          0x3C4
#define IA32_UNCORE_PERFEVTSEL5          0x3C5
#define IA32_UNCORE_PERFEVTSEL6          0x3C6
#define IA32_UNCORE_PERFEVTSEL7          0x3C7
#endif
