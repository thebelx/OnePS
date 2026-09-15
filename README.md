    # OnePS

**The solution, or another wall.** The final piece of the PS4 13.02 jailbreak equation, and you're needed.

---

## The ask, first

Run `fn_leak.html` on a PS4 13.02. It uses the SSV primitive from `core.js` to walk the kernel's socket structures down to `pru_bind`, and prints the disassembly of that function as the runtime sees it.

I need one thing: **the `FN_BYTES` block from a run where `PRIM-OK` prints.**

If you get it, paste it publicly. Here, in a gist, on X, anywhere I can read it. That block names `pru_bind` in Ghidra, which answers the question this whole project was built around.

If you don't get it, you're at one of four failure modes documented below. Cold boot and try again. The dice are the dice.

```
https://thebelx.github.io/OnePS/fn_leak.html
```

Direct to `fn_leak.html`. Do not go through `oneps.html`. The article you're reading right now is context; the file above is the tool.

---

## What this is

I started with one question: **does `pru_bind` copy the sockaddr, or retain a pointer to it?**

If it retains, then after a `bind()` call the kernel is holding a user-space pointer. Free the sockaddr, reallocate it with controlled bytes, trigger any socket operation that dereferences the stored address, and you have a use-after-free in the kernel. That's the actual vulnerability this whole chain was built to confirm or refute.

Everything else — the SSV primitive, the ROP into libkernel, the `allproc` walk, the `struct socket` extraction, the `pr_usrreqs` dereference — exists to reach one function's disassembly.

The entire chain sleeps behind one line of output. **`PRIM-OK`.** That line is the one piece.

---

## Credit

**Hassan** found the original SSV shape. The `k=2` duplicate-index trick, the predecessor fill, the `history.replaceState` collision — that's his research. Everything here is built on top of it.

13.02 offsets come from public dumps and my own Ghidra work. The `ALLPROC_RVA = 0x01CA8538` correction in this repo was derived from `procinit` at `FUN_0080e2c0` — the real value differs from the widely-published `0x01B28538` by `0x180000`. Every published table I've seen has the wrong value.

---

## Why this is hard on 13.02

Two independent gates. Both must be satisfied for the chain to reach `PRIM-OK`. Neither is controllable from JavaScript.

### Gate 1 — timing

After a cold boot, the browser's sysmemory pool is at its smallest while the OS is still bringing up services. Open too early and `ADDROF-PREP-BEGIN` OOMs. Open too late and JSC's background GC has zeroed the pages the pattern needs; you get `ZERO-HEADER-MISS hex=0000...`.

Empirically on my console, ~2 minutes after power-on is too early (OOM), and longer than ~4 minutes is too late (zeros). The window is narrow and moves per console. Sweep it on your own hardware: cold boot, open the browser at 150s, 180s, 210s, 240s, 270s, 300s, two cold boots per interval, record which interval produces the fewest OOMs and fewest zero-misses.

### Gate 2 — ASLR placement

Given that the timing window is satisfied, the SSV groom must land the fake cell on the predecessor pattern. The JSC heap base rolls per cold boot. If the pattern doesn't cover the cell's landing region, you get `ZERO-HEADER-MISS` (all zeros) or `VALIDATION-MISMATCH` (nonzero bytes from a different JSC object).

### The math

```
P(success) = P(T) × P(A | T)
```

Where `T` is the timing gate and `A` is the placement gate. Observed on my console:

| quantity | estimate | note |
|---|---|---|
| P(T) | ~0.25 | fraction of cold boots in the timing window |
| P(A \| T) | ~0.15 | fraction of in-window boots where placement lands |
| P(success) | ~0.04 | 1 in ~25 cold boots |

Two `PRIM-OK` events have been observed across the entire test history. **Two is not a statistically useful sample.** The point estimate from 2-in-30 is 6.7%, with a 95% confidence interval roughly `[0.8%, 22%]`. The 6.7% figure should be treated as a working guess with a very wide band.

The FW 11.00 reference chain hits first try because its carrier is 160 MB. That covers the entire JSC heap, so any cell the deserializer hands out is inside the pattern. On 13.02 the browser's pool caps at ~80 MB, so the carrier can't exceed ~70 MB. The pattern covers a fraction of the heap, and the missing `beforeCriticalLoad` is what substitutes for the missing memory.

---

## The four outcomes

Every cold boot ends in exactly one rung of the ladder. The only rung that matters for the success rate is the last one.

| outcome | tag | meaning |
|---|---|---|
| 0 | `OOM` | died before SSV. Timing or memory. |
| 0 | `ADDROF-FAIL source-covered=false` | long roll, carrier too small. Cold boot. |
| 1 | `Unable to deserialize` | SSV ran, state blob clobbered by slab or drains. |
| 2 | `ZERO-HEADER-MISS hex=0000...` | SSV ran, blob survived, cell landed in fresh zero pages. |
| 3 | `ZERO-HEADER-MISS hex=<nonzero>` | cell landed on real JSC data. |
| 4 | `VALIDATION-MISMATCH rw=true-holder=true...` | cell landed on pattern, walk started. |
| 5 | `READ-PRIMITIVE-PASS` / `PRIM-OK` | the one piece. |

Rungs 0 and 1 are config or timing problems. Rungs 2–4 are placement problems. Rung 5 is the win.

---

## Where the road actually ends

There is one function in `core.js` whose absence is the difference between a 4–13% per-boot rate and a rate near 100%:

```js
beforeCriticalLoad
```

`core.js` accepts an option of that name:

```js
criticalBarrier = typeof opts.beforeCriticalLoad === "function"
    ? opts.beforeCriticalLoad : defaultCriticalBarrier;
```

If you pass one, it runs between the SSV grooming and the state-blob deserialization. Its documented purpose is to nudge JSC's allocator into committing a fresh cell at exactly the fake address the pattern prepared. With it, placement is deterministic. Without it, the default is a stub that writes a string to a hidden div and creates a Blob, and does nothing to the JS heap.

The FW 11.00 reference chain doesn't need `beforeCriticalLoad` either. It wins because 160 MB of pattern covers the entire heap — any cell the allocator hands out is inside the pattern. On 13.02, no carrier is big enough. **The missing callback is what substitutes for the missing memory.**

Whoever has a working `beforeCriticalLoad` for 13.02 is holding the one piece. Every other knob — slab, pred, sep, slots, drain — is a workaround for its absence.

---

## The formula sheet

Two exact formulas, everything else empirical.

**Coverage floor.** The carrier must cover the leaked string:

```
slots ≥ (copiedLength - 8) / 4
```

The leaked string is either ~924,176 chars (short roll) or ~34,478,608 chars (long roll). So the floor is either `~231,042` slots or `~8,619,650` slots.

**Memory ceiling.** Total allocation must fit under the browser's sysmemory pool. On `fn_leak.html` after cold boot, observed ceiling is ~84 MB ±2 MB. The budget is:

```
slots × 8 + drain × drainsz + slab + pred + holes ≤ 84 MB
```

Which gives `slots ≤ ~9,175,040` with the working values of the other knobs.

**Everything else is empirical.** The working `slab` and `pred` values depend on the boot's KASLR seed and JSC's allocator state. Neither is observable from JS before the SSV runs. `slab=0x800000` and `pred=0xa0000` are landings on a per-boot curve whose shape is not visible from JavaScript. They are not derived.

---

## URL parameters

`core.js` reads them at module load. All optional — the defaults are the working config.

| parameter | default | meaning |
|---|---|---|
| `?slots=N` | 4000000 | carrier slots (N × 8 bytes) |
| `?g=drain:N` | 256 | drain count |
| `?g=drainsz:0xN` | 0x2000 | drain size |
| `?g=slab:0xN` | 0x800000 | slab size |
| `?g=pred:0xN` | 0xa0000 | predecessor size |
| `?g=sep:0xN` | 0x10000 | separator |
| `?g=guard:0xN` | 0x90000 | guard |
| `?g=early:0xN` | 0x70000 | early hole |
| `?g=final:0xN` | 0x80000 | final hole |
| `?g=bfly:0xN` | 0x81000 | butterfly hole (×2) |

**Values are `key:value`, not `key=value`.** The parser splits each `g=` entry on the first colon. `g=slab=0x800000` is silently dropped. `g=slab:0x800000` works.

The working default config is:

```
?slots=4000000&g=drain:256&g=drainsz:0x2000&g=slab:0x800000&g=pred:0xa0000
```

or just leave the URL bare and let `core.js`'s defaults apply.

---

## How to run

**Cold boot required.** Close the browser completely (Close Application from the PS4 home menu, not just back out of the tab). Power off the PS4 — and unplug it for 60 seconds. Plug back in, power on. Wait for the home screen to be fully responsive, then open the browser in the timing window you found by sweeping.

Do not open any other tab. Do not let the browser sit on the home page.

Navigate directly to:

```
https://thebelx.github.io/OnePS/fn_leak.html
```

Press nothing. The module loads, runs one SSV attempt, and either prints `PRIM-OK` or one of the failure tags. There is no button. There is no retry loop. One page load, one attempt, one roll.

If you see `AUTO-RETRY-SCHEDULED` in the log, you're running a stale cached copy of `core.js` or `fn_leak.js`. Hard-clear the browser cache or append `?v=<timestamp>` to the URL. The retry loop reuses the renderer's heap and lowers the success rate.

### What to paste

If `PRIM-OK` prints, the walk runs. Paste the block that starts with `FN-HEAD` and ends with the last `FN_BYTES` line. That's `pru_bind`'s disassembly as the runtime sees it.

```
FN-HEAD  fn=0xffffffff8........
FN_RVA   0x........
FN_HINT  1302.elf.c  ->  FUN_........
FN_BYTES  (16 lines of hex)
```

That block names the Ghidra function. Open `1302.elf.c` in Ghidra, `G` to that address, read the body.

If `PRIM-OK` doesn't print, you got one of the four outcomes above. Cold boot and try again.

### What not to paste

Any line above `PRIM-OK` other than `KBASE-PROBE`, `ALLPROC`, `PROC`, `SO`, or `PRU`. Those are diagnostic. Everything else is either the dice roll or a config issue that's already documented.

---

## Portability

Everything here is 13.02.

`beforeCriticalLoad` is **likely portable** to the rest of the 13.x line, because it operates on JSC's allocator, not on the kernel. The JSC deduplication bug that lets a `history.state` clone alias a freed cell is a JavaScriptCore bug, not a Sony bug. If the same shape of `history.replaceState` call produces the same deserialization path on 13.04 as it does on 13.02, the callback should work unchanged, and so should the JS-side heap shaping in `core.js`.

Every offset in `ps4_offsets.js` is **not portable**. The kernel RVAs, the libkernel stub table, the WebKit gadget offsets, and the anchors (`k__error`, `wk_expm1_builtin`, `k_kl_lock`, `k_sysent_661`, `allproc`) are compiled into a specific firmware build. On 13.04 they are all different. Anyone porting has to re-derive every one from their own kernel dump.

For 13.50 and 13.52 I have nothing. I don't know if the callback ports, I don't know if the SSV bug is present in their WebKit build, I don't know if the offsets are anywhere near 13.04's. Those are hypotheses worth testing, not results.

**Disclaimer.** I have personally tested this chain on 13.02 and only 13.02. Everything above about 13.04, 13.50, and 13.52 is reasoning, not empirical result. It may be wrong. Do not take it as a guarantee — take it as a hypothesis worth testing. If you get any non-13.02 result, please reach out.

---

## Files

| file | purpose |
|---|---|
| `fn_leak.html` | the tool. One page load, one attempt. |
| `fn_leak.js` | the walk. Imports from `core.js`, `int64.js`, `ps4_offsets.js`. |
| `core.js` | SSV grooming and the primitive. Where `beforeCriticalLoad` is missing. |
| `int64.js` | 64-bit arithmetic. Stores the low half as `.low`, three letters. |
| `ps4_offsets.js` | 13.02 offsets. `ALLPROC_addr` is corrected here. |

If you want the article as a standalone page, host it at `article.html` or link to `oneps.html` — but the oneps launcher performs a second navigation before loading `fn_leak.js`, which wastes the fresh heap. **Use `fn_leak.html` directly.**

---

## The one line

Everything in this chain depends on one value. On 13.02, that value is `beforeCriticalLoad`. Whoever produces a working one has the one piece.

Find it, and every cold boot lands. Every OOM goes away. Every `ZERO-HEADER-MISS` goes away. The chain runs first try like the 11.00 reference does.

Until then: cold boot, roll, cold boot, roll.

---

**bel** — [jb.0d01.wtf](https://jb.0d01.wtf) · [@belsploit](https://x.com/belsploit)