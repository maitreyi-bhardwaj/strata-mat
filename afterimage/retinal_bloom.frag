// ============================================================================
//  AFTERIMAGE — "RETINAL BLOOM"
//  Fragment shader for a 270° wrap-around projection canvas.
//
//  Concept: bioluminescent filaments drift through a black void like fluid
//  currents. Every filament leaves behind a decaying ghost in its
//  COMPLEMENTARY hue, the way a bright light leaves a negative afterimage on
//  the retina. Large domain-warped structures read from across the room;
//  pixel-locked contour "fingerprints" and plankton sparks reveal themselves
//  only when a visitor stands inches from the wall.
//
//  Target: GLSL ES 1.00 (WebGL1) — also compiles as WebGL2 via a #version
//  300 es wrapper (rename gl_FragColor). No derivatives / extensions needed.
// ============================================================================

#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;   // 18K-wide canvases overflow mediump coordinates
#else
precision mediump float;
#endif

// ---------------------------------------------------------------------------
//  STANDARD UNIFORMS
// ---------------------------------------------------------------------------
uniform vec2  u_resolution;     // canvas size in pixels
uniform float u_time;           // seconds since start (real time)
uniform vec2  u_mouse;          // pointer / tracked-visitor position, pixels

// ---------------------------------------------------------------------------
//  CUSTOM UNIFORMS  (map these to Figma Agent sidebar variables)
//  Recommended defaults in [brackets]. Unbound uniforms read as 0.0.
// ---------------------------------------------------------------------------
uniform float u_speed;          // [0.35] 0.0–2.0  flow speed of the currents
uniform float u_frequency;      // [1.40] 0.5–4.0  size of global structures (higher = smaller)
uniform float u_glow_intensity; // [1.20] 0.0–3.0  filament brightness / bloom
uniform float u_warp;           // [1.60] 0.0–3.0  domain-warp strength (fluid turbulence)
uniform float u_afterimage;     // [0.65] 0.0–1.0  strength of complementary ghost trails
uniform float u_trail_lag;      // [0.45] 0.05–1.5 seconds between ghost echoes
uniform float u_micro_detail;   // [0.50] 0.0–1.0  close-range texture visibility
uniform float u_micro_scale;    // [18.0] 6–64     micro texture cell size, in PIXELS
uniform float u_hue_shift;      // [0.00] 0.0–1.0  rotates the whole palette
uniform float u_phase;          // [0.00] 0.0–1.0  scene state, driven by Figma Motion
uniform float u_center_weight;  // [0.60] 0.0–1.0  how strongly energy pools at centre
uniform float u_mouse_radius;   // [0.35] 0.05–1.0 radius of the visitor "gravity lens"

// ---------------------------------------------------------------------------
//  CONSTANTS
// ---------------------------------------------------------------------------
const float TAU           = 6.28318530718;
const float BREATH_PERIOD = 12.0;  // seconds of REAL time — the master clock
                                   // that Figma Motion durations lock onto
const int   GHOSTS        = 3;     // afterimage echoes (cost scales linearly)

// ============================================================================
//  1. SIMPLEX NOISE 3D
//  Ashima Arts / Stefan Gustavson, MIT licence.
//  Space is skewed onto a tetrahedral lattice; each of the 4 surrounding
//  corners contributes  (0.6 - r²)^4 * dot(gradient, offset).
//  Output ≈ [-1, 1], smooth (C2), no axis-aligned artefacts.
// ============================================================================
vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec4 mod289(vec4 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec4 permute(vec4 x) { return mod289(((x * 34.0) + 1.0) * x); }
vec4 taylorInvSqrt(vec4 r) { return 1.79284291400159 - 0.85373472095314 * r; }

float snoise(vec3 v) {
    const vec2 C = vec2(1.0 / 6.0, 1.0 / 3.0);
    const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);

    // Skew input space to find the containing simplex cell
    vec3 i  = floor(v + dot(v, C.yyy));
    vec3 x0 = v - i + dot(i, C.xxx);

    // Rank the components to pick which tetrahedron of the cube we are in
    vec3 g  = step(x0.yzx, x0.xyz);
    vec3 l  = 1.0 - g;
    vec3 i1 = min(g.xyz, l.zxy);
    vec3 i2 = max(g.xyz, l.zxy);

    // Offsets from the remaining three corners
    vec3 x1 = x0 - i1 + C.xxx;
    vec3 x2 = x0 - i2 + C.yyy;
    vec3 x3 = x0 - D.yyy;

    // Hash the 4 corners into pseudo-random gradient indices
    i = mod289(i);
    vec4 p = permute(permute(permute(
                 i.z + vec4(0.0, i1.z, i2.z, 1.0))
               + i.y + vec4(0.0, i1.y, i2.y, 1.0))
               + i.x + vec4(0.0, i1.x, i2.x, 1.0));

    // Map hashes onto 49 gradient directions on an octahedron
    float n_ = 0.142857142857; // 1/7
    vec3  ns = n_ * D.wyz - D.xzx;
    vec4  j  = p - 49.0 * floor(p * ns.z * ns.z);
    vec4  x_ = floor(j * ns.z);
    vec4  y_ = floor(j - 7.0 * x_);
    vec4  x  = x_ * ns.x + ns.yyyy;
    vec4  y  = y_ * ns.x + ns.yyyy;
    vec4  h  = 1.0 - abs(x) - abs(y);
    vec4  b0 = vec4(x.xy, y.xy);
    vec4  b1 = vec4(x.zw, y.zw);
    vec4  s0 = floor(b0) * 2.0 + 1.0;
    vec4  s1 = floor(b1) * 2.0 + 1.0;
    vec4  sh = -step(h, vec4(0.0));
    vec4  a0 = b0.xzyw + s0.xzyw * sh.xxyy;
    vec4  a1 = b1.xzyw + s1.xzyw * sh.zzww;
    vec3  p0 = vec3(a0.xy, h.x);
    vec3  p1 = vec3(a0.zw, h.y);
    vec3  p2 = vec3(a1.xy, h.z);
    vec3  p3 = vec3(a1.zw, h.w);

    // Normalise gradients
    vec4 norm = taylorInvSqrt(vec4(dot(p0, p0), dot(p1, p1), dot(p2, p2), dot(p3, p3)));
    p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;

    // Radial falloff kernel (0.6 - r²)^4, then sum dot(gradient, offset)
    vec4 m = max(0.6 - vec4(dot(x0, x0), dot(x1, x1), dot(x2, x2), dot(x3, x3)), 0.0);
    m = m * m;
    return 42.0 * dot(m * m, vec4(dot(p0, x0), dot(p1, x1), dot(p2, x2), dot(p3, x3)));
}

// ============================================================================
//  2. FRACTAL BROWNIAN MOTION
//  fbm(p) = Σ  0.5^k * snoise(R^k * 2.02^k * p)
//  Each octave doubles frequency and halves amplitude. The rotation matrix R
//  (≈36.87°) decorrelates octaves so grid-aligned seams never stack up.
// ============================================================================
const mat2 ROT = mat2(0.80, 0.60, -0.60, 0.80);

float fbm4(vec3 p) {                 // full detail — the hero layer
    float sum = 0.0, amp = 0.5;
    for (int i = 0; i < 4; i++) {
        sum  += amp * snoise(p);
        p.xy  = ROT * p.xy * 2.02;
        p.z  *= 1.07;                // octaves evolve at slightly different rates
        amp  *= 0.5;
    }
    return sum;
}

float fbm2(vec3 p) {                 // cheap — warp vectors and ghost echoes
    float sum = 0.5 * snoise(p);
    p.xy = ROT * p.xy * 2.02;
    return sum + 0.25 * snoise(p * vec3(1.0, 1.0, 1.07));
}

// ============================================================================
//  3. COLOUR — cosine palette (Iñigo Quílez)
//  colour(x) = a + b * cos( 2π (c·x + d) )
//  a = mid level (kept low → deep blacks), b = swing, d = per-channel phase.
//  Phases chosen to sweep cyan → violet → magenta → teal (bioluminescent).
// ============================================================================
vec3 palette(float x) {
    vec3 a = vec3(0.30, 0.32, 0.45);
    vec3 b = vec3(0.30, 0.32, 0.45);
    vec3 c = vec3(1.00, 1.00, 1.00);
    vec3 d = vec3(0.62, 0.30, 0.15) + u_hue_shift;
    return a + b * cos(TAU * (c * x + d));
}

// Complementary colour for the afterimage: rotate palette phase by half a
// cycle (cos(θ+π) = -cos θ), which mirrors each channel around its mid level.
vec3 ghostPalette(float x) {
    return palette(x + 0.5);
}

// Cheap 2D hash → [0,1). Used for sparks and dithering, never for structure.
float hash12(vec2 p) {
    vec3 p3 = fract(vec3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return fract((p3.x + p3.y) * p3.z);
}

// ============================================================================
//  4. THE TENDRIL FIELD
//  Returns  x = filament luminance,  y = local turbulence (drives hue).
//
//  Step A  s  = (p · frequency, t)                       — 3D sample point
//  Step B  q  = (fbm(s), fbm(s + offset))                — warp vector field
//  Step C  n  = fbm(s + warp · q)                        — warped scalar field
//  Step D  d  = |fract(n · BANDS) − 0.5| · 2             — distance to nearest
//                                                          iso-contour of n
//  Step E  glow = e^(−40d) + 0.35·e^(−12d)               — sharp core + soft halo
//  Step F  × life mask (another noise)                   — filaments fade in/out
//          along their length instead of forming closed rings
// ============================================================================
vec2 tendrils(vec2 p, float t, float phase, bool hiDetail) {
    // Step A — phase pushes us through the noise volume, so a Figma-eased
    // phase change produces a matching morph of the whole structure.
    vec3 s = vec3(p * u_frequency, t * 0.07 + phase * 1.5);

    // Step B — two decorrelated fbm samples form a 2D displacement vector
    vec2 q = vec2(fbm2(s),
                  fbm2(s + vec3(5.2, 1.3, 2.8)));

    // Step C — displace the domain by q: straight lines become fluid currents
    float warp = u_warp * (0.7 + 0.6 * phase);
    vec3  s2   = vec3(s.xy + warp * q, t * 0.11);
    float n    = hiDetail ? fbm4(s2) : fbm2(s2);

    // Step D — contour distance. fract() repeats every 1/BANDS of n, so each
    // repetition is one filament; |x−0.5|·2 is 0 on the filament centre line.
    const float BANDS = 5.0;
    float d = abs(fract(n * BANDS) - 0.5) * 2.0;

    // Step E — exponential falloff = smooth glow without any hard edge
    // (minus e^(−12), so the halo tail reaches exactly 0 between filaments)
    float glow = exp(-d * 40.0) + 0.35 * max(exp(-d * 12.0) - exp(-12.0), 0.0);

    // Step F — life mask: smoothstep on low-frequency noise gates filaments
    float life = smoothstep(-0.25, 0.55, snoise(vec3(s.xy * 0.5 + q, t * 0.05 + 9.0)));

    return vec2(glow * life, length(q));
}

// ============================================================================
//  5. MAIN
// ============================================================================
void main() {
    vec2  frag   = gl_FragCoord.xy;
    float aspect = u_resolution.x / u_resolution.y;

    // --- 5.1 Coordinates ---------------------------------------------------
    // Normalise by HEIGHT so structures keep their size on any panorama ratio.
    // p.y ∈ [−0.5, 0.5],  p.x ∈ [−aspect/2, aspect/2],  origin at canvas centre.
    vec2 p = (frag - 0.5 * u_resolution) / u_resolution.y;

    // edge ∈ [0,1]: 0 at centre, 1 at the far left/right seams of the wrap
    float edge = abs(p.x) / (0.5 * aspect);

    // --- 5.2 Time ----------------------------------------------------------
    float t      = u_time * u_speed;              // flow clock (artist-scaled)
    float phase  = clamp(u_phase, 0.0, 1.0);      // Figma-eased scene state
    // Breath: raised cosine on REAL time, 0 → 1 → 0 every BREATH_PERIOD secs.
    // Independent of u_speed so Figma's timeline can lock onto it.
    float breath = 0.5 - 0.5 * cos(TAU * u_time / BREATH_PERIOD);

    // --- 5.3 Edge bleed ----------------------------------------------------
    // Toward the wrap seams, zoom the domain out slightly (p · (1 + 0.35e²)):
    // structures get finer and dimmer so the math dissolves into the corners
    // instead of hitting a hard frame edge.
    p *= 1.0 + 0.35 * edge * edge;

    // --- 5.4 Visitor gravity lens -----------------------------------------
    // Gaussian pull toward the pointer: offset = (m − p) · k · e^(−|m−p|²/r²).
    // Space bends toward the visitor like a lens, filaments curl around them.
    vec2  m     = (u_mouse - 0.5 * u_resolution) / u_resolution.y;
    vec2  toM   = m - p;
    float r     = max(u_mouse_radius, 0.05);
    float lens  = exp(-dot(toM, toM) / (r * r));
    p += toM * 0.45 * lens;

    // --- 5.5 Hero filaments (present moment) -------------------------------
    vec2  f     = tendrils(p, t, phase, true);
    float hue   = 0.15 * f.y + 0.025 * p.x + 0.08 * breath;   // hue drifts with turbulence
    vec3  col   = palette(hue) * f.x;

    // --- 5.6 Afterimage ghosts (the past) ----------------------------------
    // Re-evaluate the field at earlier times t − k·lag. Each echo:
    //   • uses the complementary palette  (negative afterimage),
    //   • decays geometrically            (0.55^k),
    //   • rises slowly upward             (retinal drift, 0.012·k),
    //   • uses cheap 2-octave noise       (ghosts are blurry — saves GPU).
    vec3 ghosts = vec3(0.0);
    float decay = 1.0;
    for (int k = 1; k <= GHOSTS; k++) {
        float fk = float(k);
        decay   *= 0.55;
        vec2  gp = p + vec2(0.0, 0.012 * fk);
        vec2  g  = tendrils(gp, t - fk * u_trail_lag * u_speed, phase, false);
        ghosts  += ghostPalette(hue + 0.03 * fk) * g.x * decay;
    }
    // Only show a ghost where the present filament is NOT: (1 − f) keeps the
    // afterimage in the negative space, never washing over the hero line.
    col += ghosts * u_afterimage * (1.0 - clamp(f.x, 0.0, 1.0)) * 1.6;

    // --- 5.7 Micro texture (revealed at arm's length) ----------------------
    // Built in PIXEL units (frag / u_micro_scale), so it stays a fixed physical
    // size on the wall regardless of the global zoom.
    float ms   = max(u_micro_scale, 4.0);
    vec2  mp   = frag / ms;
    // (a) Fingerprint contours: iso-lines of a slow noise, 6 per unit
    float mn   = snoise(vec3(mp * 0.12, t * 0.15));
    float mline = exp(-abs(fract(mn * 6.0) - 0.5) * 2.0 * 14.0);
    // (b) Plankton sparks: one hashed cell in ~200 blinks with a sine pulse
    vec2  cell  = floor(mp);
    float hc    = hash12(cell);
    float spark = step(0.995, hc) * pow(0.5 + 0.5 * sin(u_time * (1.5 + 3.0 * hc) + hc * TAU), 8.0);
    // Mask by the filament halo so dark areas stay truly dark
    float mmask = smoothstep(0.02, 0.4, f.x + 0.5 * dot(ghosts, vec3(0.33)));
    col += palette(hue + 0.25) * (mline * 0.35 + spark * 1.5) * mmask * u_micro_detail;

    // --- 5.8 Global composition --------------------------------------------
    // Gaussian centre weighting across the panorama: e^(−2.2·edge²).
    // u_center_weight blends between uniform (0) and centre-pooled (1).
    float centre = mix(1.0, exp(-2.2 * edge * edge), u_center_weight);
    // Soft vertical falloff keeps floor/ceiling seams from glowing hard.
    centre *= 1.0 - 0.35 * pow(abs(p.y) * 2.0, 3.0);

    // Intensity: dormant (phase 0) → bloom (phase 1), plus a ±15% breath.
    float energy = mix(0.35, 1.0, phase) * (0.85 + 0.30 * breath);
    col *= u_glow_intensity * energy * centre;

    // Black point: subtract a small floor so faint noise tails go to true 0.
    // Gamma (5.9) lifts tiny linear values a lot: 0.01 → 0.12 — that would
    // turn the void into grey haze on a projector.
    col = max(col - 0.004, 0.0);

    // Abyssal ambient: a whisper of deep blue so blacks feel volumetric.
    // Linear 0.0012 ≈ 8/255 after gamma — just above projector black.
    col += vec3(0.0004, 0.0006, 0.0012) * centre;

    // --- 5.9 Tone mapping ---------------------------------------------------
    // Exponential tonemap 1 − e^(−x): asymptotically approaches 1, so stacked
    // glows compress smoothly instead of clipping into flat white blocks.
    col = 1.0 - exp(-col * 1.4);
    // Highlight guard: pull luminance above 0.85 back toward its own hue.
    float lum = dot(col, vec3(0.2126, 0.7152, 0.0722));
    col = mix(col, col * (0.85 / max(lum, 1e-4)), smoothstep(0.85, 1.0, lum));

    // Gamma encode (approx. sRGB)
    col = pow(max(col, 0.0), vec3(1.0 / 2.2));

    // --- 5.10 Dither ---------------------------------------------------------
    // ±0.5 LSB noise breaks 8-bit banding in the long dark gradients, which is
    // very visible on large projection surfaces.
    col += (hash12(frag + fract(u_time) * 97.0) - 0.5) / 255.0;

    gl_FragColor = vec4(col, 1.0);
}
