#!/usr/bin/env python3
"""
AVCCNMP-v1  —  Cubic-Cortex ensemble

Multiple cubic maps and cortex columns run on the voxelized block.
Each column measures:
  shadow  — orthographic silhouettes + intensity integrals
  shape   — occupancy moments, bbox aspect, occupied fraction
  surface — 6-connected exposed faces (occupancy and value-gradient)

Those measurements vote for a predictor. XOR residual stays lossless.

"Cortex" here is a 3-layer geometric stack, not a neural net:
  L1 surface/edge  (gradient + exposed faces)
  L2 shape         (moments, components proxy)
  L3 shadow        (visual-hull style silhouettes)
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from avccnmp_codec import (
    EncodeOptions,
    MAGIC,
    VERSION,
    anvoxelize,
    build_curve_order,
    build_hilbert_2d_order,
    compress as compress_v0,
    cube_side_for,
    decode_block,
    decompress as decompress_v0,
    discover_phrases,
    encode_block,
    linearize,
    pack_mode_map,
    pack_phrases,
    phrase_decode,
    phrase_encode,
    predict_vol,
    projection_modes,
    unpack_mode_map,
    unpack_phrases,
    uvarint,
    read_uvarint,
    xor_vol,
)

# ---------------------------------------------------------------------------
# Cubic family  C(t) = p t^3 + a t + b
# Cortex occupancy kernels (threshold / fold)
# ---------------------------------------------------------------------------

CUBICS = (
    (1, 5, 17),   # v0 default
    (1, 3, 11),
    (1, 7, 13),
    (1, 1, 0),
    (1, 9, 23),
)

# occupancy kernels: name, fn(byte) -> 0/1
def _occ_nonzero(v: int) -> int:
    return int(v != 0)

def _occ_highbit(v: int) -> int:
    return int(v >= 128)

def _occ_nibble(v: int) -> int:
    return int((v & 0xF0) != 0)

def _occ_cubic_fold(v: int) -> int:
    # cortex-ish fold: cubic on the value itself
    return int(((v * v * v + 5 * v + 17) & 0xFF) >= 128)

OCC_KERNELS = (
    ("nonzero", _occ_nonzero),
    ("highbit", _occ_highbit),
    ("nibble", _occ_nibble),
    ("cubic_fold", _occ_cubic_fold),
)


# ---------------------------------------------------------------------------
# Cortex measurements on one occupancy volume
# ---------------------------------------------------------------------------

def occupancy_vol(vol, side: int, kern) -> list:
    occ = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                occ[z][y][x] = kern(vol[z][y][x])
    return occ


def shadow_maps(occ, side: int) -> dict:
    """Orthographic shadows: binary silhouette + intensity (count) along axes."""
    sx = [[0] * side for _ in range(side)]  # yz
    sy = [[0] * side for _ in range(side)]  # xz
    sz = [[0] * side for _ in range(side)]  # xy
    ix = [[0] * side for _ in range(side)]
    iy = [[0] * side for _ in range(side)]
    iz = [[0] * side for _ in range(side)]
    for z in range(side):
        for y in range(side):
            acc = 0
            for x in range(side):
                acc += occ[z][y][x]
            ix[y][z] = acc
            sx[y][z] = int(acc > 0)
        for x in range(side):
            acc = 0
            for y in range(side):
                acc += occ[z][y][x]
            iy[x][z] = acc
            sy[x][z] = int(acc > 0)
    for y in range(side):
        for x in range(side):
            acc = 0
            for z in range(side):
                acc += occ[z][y][x]
            iz[x][y] = acc
            sz[x][y] = int(acc > 0)
    area_x = sum(sx[y][z] for y in range(side) for z in range(side))
    area_y = sum(sy[x][z] for x in range(side) for z in range(side))
    area_z = sum(sz[x][y] for x in range(side) for y in range(side))
    return {
        "shadow_area": (area_x, area_y, area_z),
        "shadow_area_mean": (area_x + area_y + area_z) / 3.0,
        "shadow_anisotropy": _aniso(area_x, area_y, area_z),
        "sil_x": sx,
        "sil_y": sy,
        "sil_z": sz,
        "int_x": ix,
        "int_y": iy,
        "int_z": iz,
    }


def _aniso(a, b, c) -> float:
    m = max(a, b, c, 1)
    return (abs(a - b) + abs(b - c) + abs(c - a)) / (2.0 * m)


def shape_moments(occ, side: int) -> dict:
    pts = []
    for z in range(side):
        for y in range(side):
            for x in range(side):
                if occ[z][y][x]:
                    pts.append((x, y, z))
    n = len(pts)
    frac = n / max(1, side ** 3)
    if n == 0:
        return {
            "occupied": 0,
            "frac": 0.0,
            "centroid": (0.0, 0.0, 0.0),
            "bbox": (0, 0, 0),
            "aspect": (1.0, 1.0, 1.0),
            "eigs": (0.0, 0.0, 0.0),
            "sphericity_proxy": 0.0,
        }
    cx = sum(p[0] for p in pts) / n
    cy = sum(p[1] for p in pts) / n
    cz = sum(p[2] for p in pts) / n
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    zs = [p[2] for p in pts]
    bbox = (max(xs) - min(xs) + 1, max(ys) - min(ys) + 1, max(zs) - min(zs) + 1)
    mx = max(bbox)
    aspect = (bbox[0] / mx, bbox[1] / mx, bbox[2] / mx)
    # covariance eigenvalues via 3x3 Jacobi-free cubic (analytic)
    cxx = sum((p[0] - cx) ** 2 for p in pts) / n
    cyy = sum((p[1] - cy) ** 2 for p in pts) / n
    czz = sum((p[2] - cz) ** 2 for p in pts) / n
    cxy = sum((p[0] - cx) * (p[1] - cy) for p in pts) / n
    cxz = sum((p[0] - cx) * (p[2] - cz) for p in pts) / n
    cyz = sum((p[1] - cy) * (p[2] - cz) for p in pts) / n
    eigs = _eigh3(cxx, cxy, cxz, cyy, cyz, czz)
    # sphericity proxy: 3 * min_eig / (sum eigs + eps)  — 1 if ball-like
    s = sum(eigs) + 1e-9
    sph = 3.0 * min(eigs) / s
    return {
        "occupied": n,
        "frac": frac,
        "centroid": (cx, cy, cz),
        "bbox": bbox,
        "aspect": aspect,
        "eigs": eigs,
        "sphericity_proxy": sph,
    }


def _eigh3(a, d, e, b, f, c) -> tuple[float, float, float]:
    """Eigenvalues of symmetric 3x3 [[a,d,e],[d,b,f],[e,f,c]] via characteristic poly."""
    # trace invariants
    q = (a + b + c) / 3.0
    a2, b2, c2 = a - q, b - q, c - q
    p1 = d * d + e * e + f * f
    p2 = a2 * a2 + b2 * b2 + c2 * c2 + 2 * p1
    p = math.sqrt(max(p2 / 6.0, 0.0))
    if p < 1e-12:
        return (q, q, q)
    inv = 1.0 / p
    A, D, E, B, F, C = a2 * inv, d * inv, e * inv, b2 * inv, f * inv, c2 * inv
    det = A * (B * C - F * F) - D * (D * C - E * F) + E * (D * F - B * E)
    r = det / 2.0
    r = max(-1.0, min(1.0, r))
    phi = math.acos(r) / 3.0
    eig1 = q + 2 * p * math.cos(phi)
    eig3 = q + 2 * p * math.cos(phi + 2 * math.pi / 3)
    eig2 = 3 * q - eig1 - eig3
    return tuple(sorted((eig1, eig2, eig3), reverse=True))


def surface_area(occ, side: int) -> dict:
    """6-connected exposed faces of the occupancy solid + value-agnostic."""
    faces = 0
    for z in range(side):
        for y in range(side):
            for x in range(side):
                v = occ[z][y][x]
                # six neighbors; missing neighbor counts as outside (0)
                nbs = (
                    occ[z][y][x - 1] if x else 0,
                    occ[z][y][x + 1] if x + 1 < side else 0,
                    occ[z][y - 1][x] if y else 0,
                    occ[z][y + 1][x] if y + 1 < side else 0,
                    occ[z - 1][y][x] if z else 0,
                    occ[z + 1][y][x] if z + 1 < side else 0,
                )
                for n in nbs:
                    if v != n:
                        faces += 1
    faces //= 2  # each internal face counted twice; boundary faces once — mix
    # recount properly: internal /2 + boundary
    # simpler unique count:
    faces = 0
    for z in range(side):
        for y in range(side):
            for x in range(side):
                v = occ[z][y][x]
                if x + 1 < side:
                    faces += int(v != occ[z][y][x + 1])
                else:
                    faces += int(v != 0)
                if y + 1 < side:
                    faces += int(v != occ[z][y + 1][x])
                else:
                    faces += int(v != 0)
                if z + 1 < side:
                    faces += int(v != occ[z + 1][y][x])
                else:
                    faces += int(v != 0)
    vol = sum(occ[z][y][x] for z in range(side) for y in range(side) for x in range(side))
    compactness = (6.0 * (vol ** (2 / 3)) / faces) if faces and vol else 0.0
    return {"faces": faces, "compactness": compactness, "volume": vol}


def value_surface(vol, side: int, tau: int = 16) -> int:
    faces = 0
    for z in range(side):
        for y in range(side):
            for x in range(side):
                v = vol[z][y][x]
                if x + 1 < side and abs(v - vol[z][y][x + 1]) >= tau:
                    faces += 1
                if y + 1 < side and abs(v - vol[z][y + 1][x]) >= tau:
                    faces += 1
                if z + 1 < side and abs(v - vol[z + 1][y][x]) >= tau:
                    faces += 1
    return faces


# ---------------------------------------------------------------------------
# Visual-hull style constraint from three shadows
# ---------------------------------------------------------------------------

def visual_hull(sil_x, sil_y, sil_z, side: int):
    """Voxel is inside the hull iff it sits in all three silhouettes."""
    hull = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                if sil_x[y][z] and sil_y[x][z] and sil_z[x][y]:
                    hull[z][y][x] = 1
    return hull


def hull_agreement(occ, hull, side: int) -> float:
    same = 0
    total = side ** 3
    for z in range(side):
        for y in range(side):
            for x in range(side):
                same += int(occ[z][y][x] == hull[z][y][x])
    return same / total


# ---------------------------------------------------------------------------
# Column report + fusion score
# ---------------------------------------------------------------------------

@dataclass
class ColumnReport:
    cubic: tuple
    kernel: str
    shadow_area: tuple
    shadow_anisotropy: float
    shadow_area_mean: float
    frac: float
    aspect: tuple
    sphericity: float
    surface_faces: int
    compactness: float
    value_faces: int
    hull_agree: float
    pred_zero_frac: float
    score: float


def mode_pred_zero_frac(vol, side: int) -> float:
    px, py, pz = projection_modes(vol, side)
    pred = predict_vol(px, py, pz, side)
    zeros = 0
    cap = side ** 3
    for z in range(side):
        for y in range(side):
            for x in range(side):
                if (vol[z][y][x] ^ pred[z][y][x]) == 0:
                    zeros += 1
    return zeros / cap


def warp_volume_values(vol, side: int, cubic: tuple):
    """Apply cubic to the *value* (cortex fold), keep coordinates."""
    p, a, b = cubic
    out = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                v = vol[z][y][x]
                out[z][y][x] = (p * v * v * v + a * v + b) & 0xFF
    return out


def analyze_block(block: bytes) -> list[ColumnReport]:
    side = cube_side_for(len(block))
    vol = anvoxelize(block, side)
    reports = []
    for cubic in CUBICS:
        warped = warp_volume_values(vol, side, cubic) if cubic != (1, 5, 17) else vol
        # use original volume for occupancy geometry; warped for extra surface
        for kname, kern in OCC_KERNELS:
            occ = occupancy_vol(vol if kname != "cubic_fold" else warped, side, kern)
            sh = shadow_maps(occ, side)
            sm = shape_moments(occ, side)
            sa = surface_area(occ, side)
            hull = visual_hull(sh["sil_x"], sh["sil_y"], sh["sil_z"], side)
            agree = hull_agreement(occ, hull, side)
            zf = mode_pred_zero_frac(vol, side) if kname == "nonzero" else 0.0
            vf = value_surface(vol, side)
            # fusion score: prefer high plane-agreement (hull), compact shape,
            # high predictor zeros, moderate surface (structure without noise)
            score = (
                2.0 * agree
                + 1.5 * zf
                + 0.5 * sm["sphericity_proxy"]
                + 0.3 * min(sa["compactness"], 2.0)
                + 0.2 * sm["frac"]
                - 0.15 * sh["shadow_anisotropy"]
            )
            reports.append(
                ColumnReport(
                    cubic=cubic,
                    kernel=kname,
                    shadow_area=sh["shadow_area"],
                    shadow_anisotropy=sh["shadow_anisotropy"],
                    shadow_area_mean=sh["shadow_area_mean"],
                    frac=sm["frac"],
                    aspect=sm["aspect"],
                    sphericity=sm["sphericity_proxy"],
                    surface_faces=sa["faces"],
                    compactness=sa["compactness"],
                    value_faces=vf,
                    hull_agree=agree,
                    pred_zero_frac=zf,
                    score=score,
                )
            )
    reports.sort(key=lambda r: r.score, reverse=True)
    return reports


def cortex_descriptor(block: bytes) -> dict:
    """Compact vector the next AI can consume."""
    reps = analyze_block(block)
    best = reps[0]
    # aggregate across kernels on the default cubic
    def_rows = [r for r in reps if r.cubic == (1, 5, 17)]
    return {
        "best_cubic": best.cubic,
        "best_kernel": best.kernel,
        "best_score": round(best.score, 4),
        "shadow_areas": best.shadow_area,
        "shadow_anisotropy": round(best.shadow_anisotropy, 4),
        "shape_frac": round(best.frac, 4),
        "shape_aspect": tuple(round(x, 3) for x in best.aspect),
        "sphericity": round(best.sphericity, 4),
        "surface_faces": best.surface_faces,
        "compactness": round(best.compactness, 4),
        "value_faces": best.value_faces,
        "hull_agree": round(best.hull_agree, 4),
        "pred_zero_frac": round(best.pred_zero_frac, 4),
        "n_columns": len(reps),
        "score_spread": round(reps[0].score - reps[-1].score, 4),
        "recommend_proj": best.pred_zero_frac >= 0.25 or best.hull_agree >= 0.7,
        "recommend_curve": best.sphericity >= 0.25 and best.shadow_anisotropy < 0.45,
    }


# ---------------------------------------------------------------------------
# Ensemble predictor: vote across cubics in *coordinate* curve space
# plus visual-hull occupancy prior
# ---------------------------------------------------------------------------

def ensemble_predict(vol, side: int, use_hull: bool = True):
    """
    Hypothesis 0: v0 mode-projection majority.
    Hypotheses 1..K: mode-projection after cubic *value* fold, mapped back
    by using the folded volume only as a second vote on 'structure',
    while predicted *values* still come from original-axis modes.
    Hull prior: if a cell is outside the dominant occupancy hull, bias
    toward 0 when that is consistent with a mode.
    """
    px, py, pz = projection_modes(vol, side)
    base = predict_vol(px, py, pz, side)

    # occupancy hull from nonzero kernel
    occ = occupancy_vol(vol, side, _occ_nonzero)
    sh = shadow_maps(occ, side)
    hull = visual_hull(sh["sil_x"], sh["sil_y"], sh["sil_z"], side)

    # additional mode maps from cubic-folded values — used as tie breakers
    extra_preds = []
    for cubic in CUBICS[1:3]:
        w = warp_volume_values(vol, side, cubic)
        wpx, wpy, wpz = projection_modes(w, side)
        extra_preds.append(predict_vol(wpx, wpy, wpz, side))

    pred = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                votes = [base[z][y][x]]
                for ep in extra_preds:
                    votes.append(ep[z][y][x])
                # if hull says empty and 0 is among votes, prefer 0
                if use_hull and hull[z][y][x] == 0 and 0 in votes:
                    pred[z][y][x] = 0
                    continue
                pred[z][y][x] = Counter(votes).most_common(1)[0][0]
    return pred, hull


def residual_stats(block: bytes) -> dict:
    side = cube_side_for(len(block))
    vol = anvoxelize(block, side)
    px, py, pz = projection_modes(vol, side)
    v0 = predict_vol(px, py, pz, side)
    ens, hull = ensemble_predict(vol, side, True)
    def zf(pred):
        z = 0
        cap = side ** 3
        for zz in range(side):
            for yy in range(side):
                for xx in range(side):
                    if (vol[zz][yy][xx] ^ pred[zz][yy][xx]) == 0:
                        z += 1
        return z / cap
    return {
        "v0_zero_frac": zf(v0),
        "ensemble_zero_frac": zf(ens),
        "hull_fill": sum(hull[z][y][x] for z in range(side) for y in range(side) for x in range(side))
        / (side ** 3),
        "side": side,
    }


# ---------------------------------------------------------------------------
# v1 encode path: cortex gates v0 flags, stores a 16-byte descriptor stamp
# ---------------------------------------------------------------------------

def gate_options(block: bytes) -> tuple[EncodeOptions, dict]:
    d = cortex_descriptor(block)
    opt = EncodeOptions(
        use_proj=bool(d["recommend_proj"]),
        use_curve=bool(d["recommend_curve"]),
        use_ngram=True,
        hilbert2d=False,
        curve_a=d["best_cubic"][1] if d["recommend_curve"] else 5,
        curve_b=d["best_cubic"][2] if d["recommend_curve"] else 17,
    )
    return opt, d


def compress_gated(data: bytes, block_size: int = 4096) -> bytes:
    """Per-block cortex gate, still AV01 compatible (each block carries flags)."""
    # reuse v0 container but choose options per block by encoding independently
    # then concatenating with the standard header
    from avccnmp_codec import encode_block as eb

    out = bytearray()
    out.extend(MAGIC)
    out.append(VERSION)
    out.extend(uvarint(len(data)))
    out.extend(uvarint(block_size))
    nblocks = (len(data) + block_size - 1) // block_size if data else 0
    out.extend(uvarint(nblocks))
    if not data:
        return bytes(out)
    for off in range(0, len(data), block_size):
        blk = data[off : off + block_size]
        opt, _ = gate_options(blk)
        blob = eb(blk, opt)
        out.extend(uvarint(len(blob)))
        out.extend(blob)
    return bytes(out)
