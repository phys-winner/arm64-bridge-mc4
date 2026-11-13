# Dynarmic dependency patches (checkout e77b1ba0)

Source: https://github.com/azahar-emu/dynarmic.git at
`e77b1ba0b7da7cbe93021b01a663acfe7c4dd516`, including its dependency submodules.
The bridge build (`arm64_bridge/build_arm64.ps1 -DynarmicSourceDirectory`)
compiles that checkout in place. Apply this patch before building.

## dynarmic-e77b1ba-mc4.patch

Regenerate with: `git -C <checkout> diff > arm64_bridge/patches/dynarmic-e77b1ba-mc4.patch`

Contents (all additive fixes for the MC4 A32 guest):

1. `emit_arm64_a32.cpp` — implement `IR::Term::Interpret` terminal (2026-09-14,
   this session). The A32 frontend emits Interpret for instructions the arm64 backend
   does not implement (CPS, MRS, LDM user variants, ...); the previous ASSERT_FALSE
   aborted the process when the guest executed one (observed in
   the MC4 loading state machine, SIGABRT via `std::terminate` in
   `EmitA32Terminal`). New behavior: advance past the instruction (PC += 2 Thumb /
   4 ARM) and return to the dispatcher, which JITs the next instruction. This skips
   instruction semantics and is a known correctness limitation. The upstream
   x64 backend handles the same terminal via `UserCallbacks::InterpreterFallback`.
2. `asimd.inc` + `a32_translate_impl.h` + `asimd_three_regs.cpp` — implement the
   ASIMD `VADDHN` instruction (2026-09-13, bridge-upgrade session). The decoder entry
   was commented out and the visitor missing; MC4 guest code executes VADDHN.

## Applying to a fresh checkout

```
git -C <dynarmic-checkout> apply <absolute-path-to>/arm64_bridge/patches/dynarmic-e77b1ba-mc4.patch
```

If the checkout revision moves past e77b1ba0, re-derive the hunks against the new
revision instead of force-applying.
