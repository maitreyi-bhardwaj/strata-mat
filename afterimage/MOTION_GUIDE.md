# Afterimage — "Retinal Bloom" · Figma Motion Choreography Guide

Companion to `retinal_bloom.frag`. Test-render it with `preview.html`:
run `python3 -m http.server` in this folder, then open
`localhost:8000/preview.html?aspect=12`.

---

## 0. Read first: the GLSL → Figma runtime gap

Figma's native shader runtime does **not** run GLSL. A Figma shader is a
TypeScript `main.ts` module that drives **WebGPU/WGSL**. This concept generates
its own pixels, so it would be a `fill` shader. The `.frag` file is the
reference implementation: it runs in WebGL, TouchDesigner, Shadertoy and
custom projection servers. To use it inside Figma, port it to WGSL with this
mapping:

| GLSL (this file) | Figma shader runtime |
| --- | --- |
| `u_time` (seconds) | `Number(frame.time) * 0.001` (Figma's `frame.time` is in **milliseconds**) |
| `u_resolution` | `frame.output.width`, `frame.output.height` |
| `u_mouse` | `frame.mousePosition` (layer-local pixels; **y-origin may be top-left**, while `gl_FragCoord` uses bottom-left, so flip y if the lens appears mirrored) |
| `u_speed`, `u_phase`, … | `defineProperties` → `number` + `control: "slider"` with min/max/step |
| `gl_FragCoord` | `@builtin(position)` |
| `gl_FragColor` | `fs_main` return value (fill output uses straight alpha, so return `vec4f(col, 1.0)`) |
| `mod289`, `fract`, `mix`… | same names in WGSL; `let` is immutable, so use `var` for accumulators |

Metadata the port needs: `isAnimated: true` and `usesMouse: true`.
Every slider declared in `defineProperties` can be keyframed in Figma Motion.
That is the mechanism this guide relies on.

> Accuracy caveat: Figma Motion's UI labels (panel names, where the easing
> field lives) are not verified here and may differ from what is described
> below. The cubic-bezier numbers and the timing math do not depend on the UI.

---

## 1. Sidebar variables (defaults and safe ranges)

| Variable | Default | Range | Animate in Motion? |
| --- | --- | --- | --- |
| `u_phase` | 0.0 | 0–1 | **Yes. This is the primary choreography channel.** |
| `u_glow_intensity` | 1.2 | 0–3 | Yes (accents) |
| `u_warp` | 1.6 | 0–3 | Yes (slow) |
| `u_hue_shift` | 0.0 | 0–1 | Yes (very slow) |
| `u_afterimage` | 0.65 | 0–1 | Yes |
| `u_center_weight` | 0.6 | 0–1 | Optional |
| `u_frequency` | 1.4 | 0.5–4 | Avoid (whole field rescales; can feel like a zoom lurch) |
| `u_speed` | 0.35 | 0–2 | **Never during playback (see §4.2)** |
| `u_trail_lag` | 0.45 | 0.05–1.5 | No |
| `u_micro_detail` | 0.5 | 0–1 | No |
| `u_micro_scale` | 18 | 6–64 px | No; set for the projector's physical pixel pitch |
| `u_mouse_radius` | 0.35 | 0.05–1 | No |

---

## 2. The easing curves

Every curve below keeps **y1, y2 within [0, 1]**, so there is no overshoot and no
bounce. A bounce on a wall-sized surface reads as the whole room lurching.
Velocity at the end of a curve is `(1 − y2) / (1 − x2)`. All curves except
Pressure Wave have `y2 = 1`, so **every motion ends at zero velocity** and
there are no hard stops.

| Name | `cubic-bezier` | Duration | Apply to | Feel |
| --- | --- | --- | --- | --- |
| **Tidal Swell** | `cubic-bezier(0.45, 0.00, 0.15, 1.00)` | 6 s | `u_phase` 0 → 1 (bloom) | Mass gathering: slow start, then a long weighted glide into rest |
| **Undertow** | `cubic-bezier(0.65, 0.00, 0.35, 1.00)` | 18 s | `u_phase` 1 → 0 (retreat) | Symmetric heavy in-out; the retreat is 3× slower than the bloom, so the afterimage lingers |
| **Abyssal Drift** | `cubic-bezier(0.37, 0.00, 0.63, 1.00)` | 24 s, ping-pong | `u_warp` 1.2 ↔ 2.2, `u_hue_shift` 0 ↔ 0.15 | Sine-like ambient breathing with no perceptible endpoints |
| **Pressure Wave** | `cubic-bezier(0.22, 0.61, 0.36, 1.00)` | 3 s | `u_glow_intensity` 1.2 → 2.0, then back with Undertow over 6 s | Fast attack, slow release, like bioluminescence flaring under stimulus |
| **Ghost Hold** | `cubic-bezier(0.50, 0.00, 0.10, 1.00)` | 12 s | `u_afterimage` 0.65 → 1.0 during retreat | Ghosts strengthen as the present fades, which is the "afterimage" moment |

Start velocity is `y1 / x1`. Pressure Wave is the only curve that starts
moving immediately (slope ≈ 2.8). Use it only on brightness, never on
position-like parameters (`u_warp`, `u_phase`). Sudden *brightness* reads as
life. Sudden *displacement* at room scale reads as motion sickness.

### Exercise (do this before reading on)
Compute the end velocity of `cubic-bezier(0.25, 0.1, 0.25, 1.0)` (CSS `ease`)
and of `cubic-bezier(0.42, 0, 1, 1)` (CSS `ease-in`). Which one would cause a
hard stop at the end of a 6 s bloom?
<details><summary>Answer</summary>
`ease`: (1−1)/(1−0.25) = 0 → soft landing. `ease-in`: (1−1)/(1−1) is
undefined, and the curve arrives with its maximum slope, so the motion stops
at full speed. That is a hard stop, so never end a room-scale move with
`ease-in`.
</details>

---

## 3. Choreography timeline (one 72 s loop)

All times are on **real seconds**, aligned to the shader's 12 s breath clock
(see §4.1). Markers are multiples of 6 s.

```
t(s)  0        12        24        36        48        60        72
      |---------|---------|---------|---------|---------|---------|
phase [Swell]~~~~hold 1.0~~~~~~~~~~~~~~~[====== Undertow 18s ======]
      0→1 6s                           42 ─────────────────────── 60  →0, hold to 72
glow            [PW]          [PW]                [PW]
                12            30                  48
after                                  [== Ghost Hold 12s ==]
                                       42 ──────────────── 54
warp  <~~~~~~~~~ Abyssal Drift 24 s ping-pong, continuous ~~~~~~~~~~~>
```

1. **0–6 s, Emergence.** `u_phase` 0 → 1 with Tidal Swell. Ends exactly at
   the first breath peak (t = 6 s).
2. **6–42 s, Bloom.** Hold `u_phase` at 1. Fire Pressure Wave on glow at 12,
   30 and 48 s. Those are breath troughs, so the flares fill the dips instead
   of stacking onto peaks.
3. **42–60 s, Afterimage.** `u_phase` 1 → 0 with Undertow (18 s) while
   `u_afterimage` rises with Ghost Hold. The present fades and its
   complementary ghosts stay. This is the piece's thesis moment.
4. **60–72 s, Void.** Phase 0 (dormant: sparse, 35 % energy, never black).
   The loop restarts at 72 = 6 × 12, which is phase-locked to the breath.

---

## 4. Syncing Motion with `u_time`

### 4.1 The breath clock: additive sync
Inside the shader:

```
breath = 0.5 − 0.5·cos(2π · u_time / 12)
```

This uses **real** time and is deliberately not multiplied by `u_speed`. It
is 0 at t = 0, 12, 24… and 1 at t = 6, 18, 30…. Final brightness is

```
energy = mix(0.35, 1.0, u_phase) · (0.85 + 0.30 · breath)
```

so the Figma-driven `u_phase` and the shader's internal breath **multiply**.
Motion sets the macro envelope (dormant ↔ bloom). The shader supplies a
±15 % organic pulse on top. Land Motion keyframes on multiples of 6 s, and
transitions will arrive with the pulse rather than against it.

### 4.2 Why `u_speed` must never be animated
The flow clock is `t = u_time · u_speed`. Its rate of change is

```
dt/dτ = u_speed + u_time · d(u_speed)/dτ
```

The second term grows with elapsed time. At minute 5 (`u_time` = 300), a
gentle 0.35 → 0.40 ramp over 2 s adds 300 × 0.025 = **7.5 units/s** of flow.
That is about 20× normal speed, and the field visibly lurches. A stateless
shader cannot integrate speed, so:

* keep `u_speed` fixed for a show, and
* create perceived acceleration through `u_warp` and `u_phase` instead. Phase
  also moves the noise volume (`z += 1.5 · u_phase`), so an eased phase
  change produces a structural morph whose velocity profile is exactly the
  Bezier curve you chose.

If the projection server can supply its own integrated clock
(`u_time = Σ speed·dt` computed on the CPU), `u_speed` can then be animated
safely.

### 4.3 Ghost echo timing
Ghost *k* samples the field at `t − k · u_trail_lag · u_speed`. With
defaults, the echoes trail by 0.45, 0.90 and 1.35 s of real time. A Motion
transition shorter than about 1.5 s finishes before its own ghosts catch up,
and the afterimage effect is lost. This is another reason every curve above
is ≥ 3 s.

---

## 5. Scale and projection notes (unverified against ARTECHOUSE specs)

* **Two-scale design.** Global structures are sized against wall *height*
  (`u_frequency` 1.4 ≈ 1.4 noise cells per wall height), so they read from
  across the room. Micro contours and sparks are sized in **pixels**
  (`u_micro_scale`), so they stay a fixed physical size and appear only at
  close range. Set `u_micro_scale` so one cell ≈ 1–2 cm on the wall. The
  projector pixel pitch is needed for this, and it is not known here.
* **Seams.** Energy is Gaussian-weighted to the centre and the domain is
  zoomed outward toward the left/right edges. Structures thin and dim into
  the corners instead of ending at a frame line.
* **GPU budget.** About 31 simplex evaluations per pixel (hero 9, ghosts
  3 × 7, micro 1). On a single GPU at very high resolution, render at
  0.5× scale and upscale, or set `GHOSTS` to 2. Measure on the real playback
  hardware; this estimate has not been benchmarked.
* **Black level.** The void is held at about 8/255 with dithering against
  banding. If the projectors raise black visibly, lower the ambient term in
  §5.8 of the shader.
