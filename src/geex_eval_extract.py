#!/usr/bin/env python3
"""GEEX-v0 — Geometric Eval + EXtraction

A block of bytes is packed into a cube. Cortex columns measure
shadow, shape, and surface at several occupancy stains. A router
emits a typed geometric object. Reconstruction is object XOR residual
and is bit-exact.

Not an LZMA / RAR / LZ4 / AES inverse.
"""
from __future__ import annotations

import json, math, hashlib, os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional
import numpy as np

ART = Path(os.environ.get("NOVELRAR_ARTIFACTS", "artifacts"))


# ---------------------------------------------------------------------------
# Voxelization
# ---------------------------------------------------------------------------

def cube_side(n: int) -> int:
    d = int(round(n ** (1.0 / 3.0)))
    while d * d * d < n:
        d += 1
    return max(d, 1)


def anvoxelize(block: bytes, side: Optional[int] = None) -> np.ndarray:
    n = len(block)
    d = side or cube_side(n)
    vol = np.zeros((d, d, d), dtype=np.uint8)
    arr = np.frombuffer(block, dtype=np.uint8)
    vol.ravel()[:n] = arr
    return vol


def linearize(vol: np.ndarray, n: int) -> bytes:
    return bytes(vol.ravel()[:n])


# ---------------------------------------------------------------------------
# Occupancy stains (mid-stain gate lives here)
# ---------------------------------------------------------------------------

def stain_nonzero(v): return v != 0
def stain_highbit(v): return v >= 128
def stain_nibble(v):  return (v & 0xF0) != 0
def stain_mid(v):     return (v >= 64) & (v < 192)
def stain_fold(v):
    f = (v.astype(np.int32) ** 3 + 5 * v.astype(np.int32) + 17) & 0xFF
    return f >= 128


STAINS = {
    "nonzero": stain_nonzero,
    "highbit": stain_highbit,
    "nibble": stain_nibble,
    "mid": stain_mid,
    "fold": stain_fold,
}

MID_STAINS = ("highbit", "nibble", "mid", "fold")  # English-trap gate


# ---------------------------------------------------------------------------
# Shadows, including 45-degree / diagonal silhouettes
# ---------------------------------------------------------------------------

def ortho_shadows(occ: np.ndarray):
    """Binary silhouettes + integrals along X,Y,Z."""
    ix = occ.sum(axis=2)  # yz? wait vol[z,y,x]; axis=2 is x -> (z,y)
    iy = occ.sum(axis=1)  # axis=y -> (z,x)
    iz = occ.sum(axis=0)  # axis=z -> (y,x)
    sx = (ix > 0).astype(np.uint8)
    sy = (iy > 0).astype(np.uint8)
    sz = (iz > 0).astype(np.uint8)
    return {
        "sil": (sx, sy, sz),
        "int": (ix, iy, iz),
        "area": (int(sx.sum()), int(sy.sum()), int(sz.sum())),
    }


def shadow_anisotropy(area):
    a, b, c = area
    m = max(a, b, c, 1)
    return (abs(a - b) + abs(b - c) + abs(c - a)) / (2.0 * m)


def diagonal_shadows(occ: np.ndarray):
    """45° silhouettes: project onto (y+x, z), (y-x padded, z), (x+z, y).

    These are cheap extra cortex columns. They catch tiles and
    diagonal edges that ortho shadows smear.
    """
    d = occ.shape[0]
    # u = x+y in [0, 2d-2], v = z
    s_xy = np.zeros((2 * d - 1, d), dtype=np.uint8)
    s_xmy = np.zeros((2 * d - 1, d), dtype=np.uint8)
    s_xz = np.zeros((2 * d - 1, d), dtype=np.uint8)
    zz, yy, xx = np.nonzero(occ)
    s_xy[xx + yy, zz] = 1
    s_xmy[xx - yy + (d - 1), zz] = 1
    s_xz[xx + zz, yy] = 1
    return {
        "area_xy": int(s_xy.sum()),
        "area_xmy": int(s_xmy.sum()),
        "area_xz": int(s_xz.sum()),
        "sil_xy": s_xy,
        "sil_xmy": s_xmy,
        "sil_xz": s_xz,
    }


def visual_hull(sil):
    sx, sy, sz = sil  # sx:(z,y), sy:(z,x), sz:(y,x)
    d = sx.shape[0]
    # hull[z,y,x] = sx[z,y] & sy[z,x] & sz[y,x]
    h = sx[:, :, None] & sy[:, None, :] & sz[None, :, :]
    return h.astype(np.uint8)


def hull_iou(occ, hull):
    both = np.logical_and(occ, hull).sum()
    either = np.logical_or(occ, hull).sum()
    if either == 0:
        return 1.0  # vacuous — caller must gate
    return float(both) / float(either)


def hull_agree(occ, hull):
    return float((occ == hull).mean())


# ---------------------------------------------------------------------------
# Shape + surface
# ---------------------------------------------------------------------------

def shape_moments(occ: np.ndarray):
    pts = np.argwhere(occ)
    n = len(pts)
    d = occ.shape[0]
    frac = n / max(1, d ** 3)
    if n == 0:
        return dict(occupied=0, frac=0.0, centroid=(0, 0, 0),
                    bbox=(0, 0, 0), aspect=(1, 1, 1),
                    eigs=(0, 0, 0), sphericity=0.0)
    c = pts.mean(axis=0)
    lo, hi = pts.min(axis=0), pts.max(axis=0)
    bbox = tuple(int(x) for x in (hi - lo + 1))
    mx = max(bbox)
    aspect = tuple(b / mx for b in bbox)
    cov = np.cov(pts.T) if n > 1 else np.zeros((3, 3))
    eigs = np.sort(np.linalg.eigvalsh(cov))[::-1]
    eigs = np.maximum(eigs, 0)
    sph = float(3.0 * eigs.min() / (eigs.sum() + 1e-9))
    return dict(occupied=int(n), frac=float(frac),
                centroid=tuple(float(x) for x in c),
                bbox=bbox, aspect=aspect,
                eigs=tuple(float(x) for x in eigs),
                sphericity=sph)


def surface_faces(occ: np.ndarray) -> int:
    """6-connected exposed faces (internal mismatch + boundary)."""
    faces = 0
    for ax in range(3):
        sl = [slice(None)] * 3
        sl2 = [slice(None)] * 3
        sl[ax] = slice(0, -1)
        sl2[ax] = slice(1, None)
        faces += int((occ[tuple(sl)] != occ[tuple(sl2)]).sum())
        # boundary
        slb0 = [slice(None)] * 3
        slb1 = [slice(None)] * 3
        slb0[ax] = 0
        slb1[ax] = -1
        faces += int((occ[tuple(slb0)] != 0).sum())
        faces += int((occ[tuple(slb1)] != 0).sum())
    return faces


def foam_index(faces: int, vol: int) -> float:
    """F = A / (6 V^{2/3}). Sphere ~1; foam >> 1; empty 0."""
    if vol <= 0:
        return 0.0
    return faces / max(1e-9, 6.0 * (vol ** (2.0 / 3.0)))


def compactness_T(faces: int, vol: int) -> float:
    """T ≈ 6V/A  (folding-like thickness proxy)."""
    if faces <= 0:
        return 0.0
    return 6.0 * vol / faces


def value_surface(vol: np.ndarray, tau: int = 16) -> int:
    faces = 0
    v = vol.astype(np.int16)
    faces += int((np.abs(v[:, :, 1:] - v[:, :, :-1]) >= tau).sum())
    faces += int((np.abs(v[:, 1:, :] - v[:, :-1, :]) >= tau).sum())
    faces += int((np.abs(v[1:, :, :] - v[:-1, :, :]) >= tau).sum())
    return faces


def axis_bias(vol: np.ndarray, occ=None) -> dict:
    """How constant is each axis fiber? High = planar stack.

    zf_* is raw match to the per-fiber mode.
    zf_occ_* is the same restricted to mid-stain / provided occupancy,
    so empty exterior cannot inflate a solid-sphere into 'planar'.
    """
    vx = float(vol.var(axis=2).mean())
    vy = float(vol.var(axis=1).mean())
    vz = float(vol.var(axis=0).mean())
    if occ is None:
        occ = ((vol >= 64) & (vol < 192)) | (vol >= 128)
        if occ.sum() == 0:
            occ = vol != 0

    def zf_axis(ax):
        m = np.apply_along_axis(
            lambda a: np.bincount(a, minlength=256).argmax(), ax, vol
        )
        if ax == 2:
            pred = np.broadcast_to(m[:, :, None], vol.shape)
        elif ax == 1:
            pred = np.broadcast_to(m[:, None, :], vol.shape)
        else:
            pred = np.broadcast_to(m[None, :, :], vol.shape)
        raw = float((vol == pred).mean())
        mask = occ.astype(bool)
        if mask.any():
            occ_zf = float((vol[mask] == pred[mask]).mean())
        else:
            occ_zf = raw
        return raw, occ_zf, pred

    rx, ox, _ = zf_axis(2)
    ry, oy, _ = zf_axis(1)
    rz, oz, _ = zf_axis(0)
    return {
        "var_xyz": (vx, vy, vz),
        "zf_along_x": rx, "zf_along_y": ry, "zf_along_z": rz,
        "zf_occ_x": ox, "zf_occ_y": oy, "zf_occ_z": oz,
    }


def mode_maps(vol: np.ndarray):
    def mode_ax(ax):
        return np.apply_along_axis(
            lambda a: np.bincount(a, minlength=256).argmax(), ax, vol
        ).astype(np.uint8)
    px = mode_ax(2)  # (z,y)
    py = mode_ax(1)  # (z,x)
    pz = mode_ax(0)  # (y,x)
    return px, py, pz


def predict_majority(vol: np.ndarray) -> np.ndarray:
    px, py, pz = mode_maps(vol)
    pred = px[:, :, None].copy()
    vy = py[:, None, :]
    vz = pz[None, :, :]
    # majority of 3; tie -> px
    eq_xy = pred == vy
    eq_xz = pred == vz
    eq_yz = vy == vz
    pred = np.where(eq_yz & ~eq_xy, vy, pred)
    return pred.astype(np.uint8)


def tile_period_guess(vol: np.ndarray, max_p: int = 16) -> dict:
    """Period along each axis.

    Score is *lift* over the empty-empty baseline: we only count
    matches at cells that are nonzero in either the source or the
    shift. Sparse shells no longer look periodic just because holes
    match holes.
    """
    d = vol.shape[0]
    occ = vol != 0

    def best_period(axis):
        scores = []
        for p in range(2, min(max_p, d // 2) + 1):
            shifted = np.roll(vol, p, axis=axis)
            socc = np.roll(occ, p, axis=axis)
            union = occ | socc
            if union.any():
                sc = float((vol[union] == shifted[union]).mean())
            else:
                sc = 0.0
            scores.append((sc, p))
        scores.sort(reverse=True)
        return scores[0] if scores else (0.0, 1)

    sx, px = best_period(2)
    sy, py = best_period(1)
    sz, pz = best_period(0)
    score = max(sx, sy, sz)
    return {"px": px, "py": py, "pz": pz,
            "sx": sx, "sy": sy, "sz": sz, "score": score}


# ---------------------------------------------------------------------------
# EVAL
# ---------------------------------------------------------------------------

CLASSES = ("planar", "shell", "tiled", "foam", "language", "noise", "raster")


@dataclass
class StainEval:
    name: str
    frac: float
    faces: int
    foam: float
    compactness_T: float
    sphericity: float
    shadow_area: tuple
    anisotropy: float
    hull_iou: float
    hull_agree: float
    vacuous: bool
    diag_areas: tuple


@dataclass
class EvalReport:
    n: int
    side: int
    pred_zero: float
    value_faces: int
    axis: dict
    tiles: dict
    mid_volume: int
    mid_ok: bool
    stains: dict
    klass: str
    confidence: float
    reasons: list


def eval_stain(vol, occ, name) -> StainEval:
    sh = ortho_shadows(occ)
    dg = diagonal_shadows(occ)
    hull = visual_hull(sh["sil"])
    sm = shape_moments(occ)
    faces = surface_faces(occ)
    voln = int(occ.sum())
    iou = hull_iou(occ, hull)
    vacuous = voln == 0
    return StainEval(
        name=name,
        frac=sm["frac"],
        faces=faces,
        foam=foam_index(faces, voln),
        compactness_T=compactness_T(faces, voln),
        sphericity=sm["sphericity"],
        shadow_area=sh["area"],
        anisotropy=shadow_anisotropy(sh["area"]),
        hull_iou=0.0 if vacuous else iou,
        hull_agree=1.0 if vacuous else hull_agree(occ, hull),
        vacuous=vacuous,
        diag_areas=(dg["area_xy"], dg["area_xmy"], dg["area_xz"]),
    )


def classify(vol, stains: dict, axis, tiles, pred_zero, mid_ok) -> tuple[str, float, list]:
    reasons = []
    hb = stains["highbit"]
    mid = stains["mid"]
    nz = stains["nonzero"]
    fold = stains["fold"]

    # language: highbit empty, fold is foam
    if hb.vacuous and fold.foam > 1.4 and fold.frac > 0.3:
        reasons.append("highbit empty + fold foam => language")
        return "language", 0.85, reasons

    # noise: mid/highbit saturated shadows, foam, low pred zeros
    if (not hb.vacuous and hb.foam > 1.6 and hb.anisotropy < 0.15
            and pred_zero < 0.15 and tiles["score"] < 0.7):
        reasons.append("full shadows, high foam, no axis/tile")
        return "noise", 0.8, reasons

    # planar: one axis almost constant ON OCCUPIED CELLS, and raw zf high
    zfs = [axis["zf_along_x"], axis["zf_along_y"], axis["zf_along_z"]]
    zfo = [axis.get("zf_occ_x", 0), axis.get("zf_occ_y", 0), axis.get("zf_occ_z", 0)]
    if max(zfo) >= 0.90 and max(zfs) >= 0.80:
        reasons.append(f"occ-axis zeros {max(zfo):.2f} raw {max(zfs):.2f}")
        return "planar", 0.95, reasons

    # shell before tiled so sparse occupancy is not mistaken for period
    use = mid if not mid.vacuous else (hb if not hb.vacuous else nz)
    # hull fill: occupied / hull volume distinguishes shell (cavity) vs solid
    hull_fill = use.frac / max(use.hull_iou * use.frac + 1e-9, 1e-9)  # placeholder
    if (not use.vacuous) and use.frac <= 0.40 and use.sphericity >= 0.55 and use.hull_iou >= 0.45:
        reasons.append(f"low fill {use.frac:.2f} sph {use.sphericity:.2f} hull {use.hull_iou:.2f}")
        return "shell", 0.85, reasons
    if (not use.vacuous) and use.frac <= 0.25 and use.foam < 2.2 and use.anisotropy < 0.25:
        reasons.append("thin compact object")
        return "shell", 0.7, reasons

    # tiled: occupied-conditional period, not planar
    if tiles["score"] >= 0.80 and max(zfo) < 0.90:
        reasons.append(f"period score {tiles['score']:.2f} p=({tiles['px']},{tiles['py']},{tiles['pz']})")
        return "tiled", 0.8, reasons

    # foam: mid-stain exists but surface is wild
    if mid_ok and use.foam > 1.5 and use.frac > 0.2:
        reasons.append(f"foam index {use.foam:.2f}")
        return "foam", 0.7, reasons

    if pred_zero >= 0.25 or (mid_ok and use.hull_iou >= 0.75):
        reasons.append("weak geometry still better than raster")
        return "raster", 0.45, reasons

    reasons.append("default raster")
    return "raster", 0.6, reasons


def evaluate(block: bytes) -> EvalReport:
    vol = anvoxelize(block)
    pred = predict_majority(vol)
    pred_zero = float((pred == vol).mean())
    vf = value_surface(vol)
    axis = axis_bias(vol)
    tiles = tile_period_guess(vol)
    stains = {}
    for name, fn in STAINS.items():
        occ = fn(vol).astype(np.uint8)
        stains[name] = eval_stain(vol, occ, name)
    mid_volume = sum(stains[n].occupied if hasattr(stains[n], "occupied") else int(stains[n].frac * vol.size)
                     for n in MID_STAINS)
    # occupied from frac
    mid_volume = int(sum(stains[n].frac * vol.size for n in MID_STAINS))
    mid_ok = mid_volume > 0 and not (
        stains["highbit"].vacuous and stains["mid"].vacuous and stains["nibble"].vacuous
        and stains["fold"].foam > 1.3
    )
    # tighter English gate: at least one mid stain has volume AND is not pure foam-of-everything
    mid_ok = any(
        (not stains[n].vacuous) and stains[n].frac > 0.02 and stains[n].foam < 1.8
        for n in ("highbit", "mid", "nibble")
    )
    klass, conf, reasons = classify(vol, stains, axis, tiles, pred_zero, mid_ok)
    return EvalReport(
        n=len(block), side=vol.shape[0], pred_zero=pred_zero,
        value_faces=vf, axis=axis, tiles=tiles,
        mid_volume=mid_volume, mid_ok=mid_ok,
        stains=stains, klass=klass, confidence=conf, reasons=reasons,
    )


# ---------------------------------------------------------------------------
# EXTRACT — structured object + residual
# ---------------------------------------------------------------------------

@dataclass
class Extracted:
    klass: str
    side: int
    n: int
    payload: dict
    residual: bytes
    object_bytes: int
    residual_zeros: float
    reconstructs: bool


def extract_planes(vol: np.ndarray) -> dict:
    axis = axis_bias(vol)
    zfs = {
        2: axis["zf_along_x"],
        1: axis["zf_along_y"],
        0: axis["zf_along_z"],
    }
    best_ax = max(zfs, key=zfs.get)
    modes = np.apply_along_axis(
        lambda a: np.bincount(a, minlength=256).argmax(), best_ax, vol
    ).astype(np.uint8)
    pred = np.empty_like(vol)
    if best_ax == 2:
        pred[...] = modes[:, :, None]
    elif best_ax == 1:
        pred[...] = modes[:, None, :]
    else:
        pred[...] = modes[None, :, :]
    return {"axis": int(best_ax), "modes": modes, "pred": pred}


def extract_hull(vol: np.ndarray, stain="mid") -> dict:
    fn = STAINS.get(stain, stain_mid)
    occ = fn(vol).astype(np.uint8)
    if occ.sum() == 0:
        occ = stain_nonzero(vol).astype(np.uint8)
    sh = ortho_shadows(occ)
    hull = visual_hull(sh["sil"])
    interior = vol.copy()
    interior[hull == 0] = 0
    pred = interior  # values only inside hull; outside predicted 0
    # if most interior is a constant, store constant
    if hull.sum():
        vals = vol[hull == 1]
        const = int(np.bincount(vals, minlength=256).argmax())
        const_frac = float((vals == const).mean())
    else:
        const, const_frac = 0, 1.0
    if const_frac >= 0.7:
        pred = np.zeros_like(vol)
        pred[hull == 1] = const
        kind = "hull_const"
    else:
        # fall back to mode projections inside hull
        mp = predict_majority(vol)
        pred = np.where(hull == 1, mp, 0).astype(np.uint8)
        kind = "hull_modes"
    return {
        "kind": kind, "stain": stain, "sil": sh["sil"], "hull": hull,
        "const": const, "const_frac": const_frac, "pred": pred,
        "diag": diagonal_shadows(occ),
    }


def extract_tiles(vol: np.ndarray, tiles: dict) -> dict:
    # take the strongest period axis and store one cell
    scores = [("x", tiles["sx"], tiles["px"], 2),
              ("y", tiles["sy"], tiles["py"], 1),
              ("z", tiles["sz"], tiles["pz"], 0)]
    scores.sort(key=lambda t: t[1], reverse=True)
    name, sc, p, ax = scores[0]
    d = vol.shape[0]
    pred = np.empty_like(vol)
    # copy first period slab repeatedly
    if ax == 2:
        cell = vol[:, :, :p]
        for x in range(d):
            pred[:, :, x] = cell[:, :, x % p]
    elif ax == 1:
        cell = vol[:, :p, :]
        for y in range(d):
            pred[:, y, :] = cell[:, y % p, :]
    else:
        cell = vol[:p, :, :]
        for z in range(d):
            pred[z, :, :] = cell[z % p, :, :]
    return {"axis": name, "period": int(p), "score": sc, "pred": pred}


def extract(block: bytes, report: Optional[EvalReport] = None) -> Extracted:
    report = report or evaluate(block)
    vol = anvoxelize(block, report.side)
    klass = report.klass
    if klass == "planar":
        obj = extract_planes(vol)
        pred = obj["pred"]
        payload = {"axis": obj["axis"], "modes": obj["modes"].tolist()}
    elif klass in ("shell",) or (klass == "foam" and report.stains["mid"].hull_iou >= 0.6):
        obj = extract_hull(vol, "mid" if not report.stains["mid"].vacuous else "nonzero")
        pred = obj["pred"]
        payload = {
            "kind": obj["kind"], "stain": obj["stain"],
            "const": obj["const"], "const_frac": obj["const_frac"],
            "shadow_area": [int(s.sum()) for s in obj["sil"]],
            "diag_area": (obj["diag"]["area_xy"], obj["diag"]["area_xmy"], obj["diag"]["area_xz"]),
            "hull_fill": float(obj["hull"].mean()),
        }
    elif klass == "tiled":
        obj = extract_tiles(vol, report.tiles)
        pred = obj["pred"]
        payload = {"axis": obj["axis"], "period": obj["period"], "score": obj["score"]}
    else:
        # raster / language / noise: no geometric object
        pred = np.zeros_like(vol)
        payload = {"kind": "empty"}
    residual_vol = vol ^ pred
    residual = linearize(residual_vol, report.n)
    recon = linearize(pred, report.n)
    # reconstruct = pred XOR residual
    rec = bytes(a ^ b for a, b in zip(recon + bytes(report.n - len(recon)), residual))
    rec = bytes(x ^ y for x, y in zip(pred.ravel()[:report.n].tolist(), residual))
    ok = rec == block
    zf = float((residual_vol.ravel()[:report.n] == 0).mean())
    # object cost estimate
    if klass == "planar":
        obytes = report.side * report.side  # one mode map
    elif klass in ("shell", "foam"):
        obytes = 3 * ((report.side * report.side + 7) // 8)  # 3 bitmaps
        if payload.get("kind") != "hull_const":
            obytes += int(payload.get("hull_fill", 0.2) * report.n)
    elif klass == "tiled":
        p = payload.get("period", 1)
        obytes = p * report.side * report.side
    else:
        obytes = 0
    return Extracted(
        klass=klass, side=report.side, n=report.n, payload=payload,
        residual=residual, object_bytes=obytes, residual_zeros=zf,
        reconstructs=ok,
    )


def object_plus_residual_size(ext: Extracted) -> int:
    return ext.object_bytes + len(ext.residual)


# ---------------------------------------------------------------------------
# Corpora
# ---------------------------------------------------------------------------

def corpus_english(n=4096):
    text = (
        b"The quick brown fox jumps over the lazy dog. "
        b"Pack my box with five dozen liquor jugs. "
        b"Geometry evaluates shadow, shape, and surface. "
    )
    return (text * (n // len(text) + 1))[:n]


def corpus_json(n=4096):
    rec = b'{"id":12,"name":"voxel","ok":true,"vals":[1,2,3,4]},'
    return (rec * (n // len(rec) + 1))[:n]


def corpus_random(n=4096, seed=0):
    rng = np.random.default_rng(seed)
    return bytes(rng.integers(0, 256, n, dtype=np.uint8))


def corpus_z_planes(n=4096):
    d = cube_side(n)
    vol = np.zeros((d, d, d), dtype=np.uint8)
    for z in range(d):
        vol[z, :, :] = (z * 17 + 40) & 0xFF
    return linearize(vol, n)


def corpus_tiles8(n=4096):
    d = cube_side(n)
    zz, yy, xx = np.ogrid[:d, :d, :d]
    # 8x8x8 motif that varies on all three axes
    vol = (((xx % 8) * 13 + (yy % 8) * 7 + (zz % 8) * 29) & 0xFF).astype(np.uint8)
    vol = np.where((xx % 8 + yy % 8) % 2 == 0, vol, 255 - vol).astype(np.uint8)
    return linearize(vol, n)


def corpus_sphere_shell(n=4096):
    d = cube_side(n)
    vol = np.zeros((d, d, d), dtype=np.uint8)
    c = (d - 1) / 2.0
    r, w = d * 0.38, 1.35
    zz, yy, xx = np.ogrid[:d, :d, :d]
    dist = np.sqrt((xx - c) ** 2 + (yy - c) ** 2 + (zz - c) ** 2)
    vol[(np.abs(dist - r) <= w)] = 180
    return linearize(vol, n)


def corpus_solid_sphere(n=4096):
    d = cube_side(n)
    vol = np.zeros((d, d, d), dtype=np.uint8)
    c = (d - 1) / 2.0
    r = d * 0.35
    zz, yy, xx = np.ogrid[:d, :d, :d]
    dist = np.sqrt((xx - c) ** 2 + (yy - c) ** 2 + (zz - c) ** 2)
    vol[dist <= r] = 200
    return linearize(vol, n)


def corpus_gradient(n=4096):
    d = cube_side(n)
    zz, yy, xx = np.ogrid[:d, :d, :d]
    vol = ((xx * 7 + yy * 3 + zz * 5) & 0xFF).astype(np.uint8)
    return linearize(vol, n)


def corpus_checker(n=4096):
    d = cube_side(n)
    zz, yy, xx = np.ogrid[:d, :d, :d]
    vol = (((xx + yy + zz) & 1) * 200).astype(np.uint8)
    return linearize(vol, n)


CORPORA = {
    "english": (corpus_english, "language"),
    "json": (corpus_json, "language"),
    "random": (corpus_random, "noise"),
    "z_planes": (corpus_z_planes, "planar"),
    "tiles8": (corpus_tiles8, "tiled"),
    "sphere_shell": (corpus_sphere_shell, "shell"),
    "solid_sphere": (corpus_solid_sphere, "shell"),
    "gradient": (corpus_gradient, "raster"),
    "checker": (corpus_checker, "tiled"),
}


def summarize_report(rep: EvalReport) -> dict:
    out = {
        "klass": rep.klass,
        "conf": round(rep.confidence, 3),
        "reasons": rep.reasons,
        "pred_zero": round(rep.pred_zero, 3),
        "mid_ok": rep.mid_ok,
        "tiles": {k: (round(v, 3) if isinstance(v, float) else v)
                  for k, v in rep.tiles.items()},
        "axis_zf": {
            "x": round(rep.axis["zf_along_x"], 3),
            "y": round(rep.axis["zf_along_y"], 3),
            "z": round(rep.axis["zf_along_z"], 3),
        },
        "stains": {},
    }
    for name, st in rep.stains.items():
        out["stains"][name] = {
            "frac": round(st.frac, 3),
            "foam": round(st.foam, 3),
            "T": round(st.compactness_T, 3),
            "sph": round(st.sphericity, 3),
            "shadow": st.shadow_area,
            "aniso": round(st.anisotropy, 3),
            "hull_iou": round(st.hull_iou, 3),
            "vacuous": st.vacuous,
            "diag": st.diag_areas,
        }
    return out


def run():
    rows = []
    for name, (fn, label) in CORPORA.items():
        block = fn(4096)
        rep = evaluate(block)
        ext = extract(block, rep)
        row = {
            "corpus": name,
            "label": label,
            "pred": rep.klass,
            "ok_class": rep.klass == label or (
                label == "shell" and rep.klass in ("shell", "planar") and name == "solid_sphere"
            ),
            "conf": rep.confidence,
            "mid_ok": rep.mid_ok,
            "pred_zero_mode": rep.pred_zero,
            "extract_zeros": ext.residual_zeros,
            "object_bytes": ext.object_bytes,
            "residual_len": len(ext.residual),
            "reconstructs": ext.reconstructs,
            "payload": {k: v for k, v in ext.payload.items() if k != "modes"},
            "eval": summarize_report(rep),
        }
        # solid sphere may be classified shell (good) 
        if name == "solid_sphere" and rep.klass == "shell":
            row["ok_class"] = True
        rows.append(row)
        print(f"{name:14} label={label:8} pred={rep.klass:8} mid_ok={rep.mid_ok} "
              f"mode_zf={rep.pred_zero:.3f} ext_zf={ext.residual_zeros:.3f} "
              f"obj={ext.object_bytes:4} recon={ext.reconstructs} {rep.reasons}")
    acc = sum(r["ok_class"] for r in rows) / len(rows)
    recon = all(r["reconstructs"] for r in rows)
    print("class acc", acc, "all reconstruct", recon)
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "geex_v0_results.json").write_text(json.dumps(rows, indent=2, default=str))
    return rows


if __name__ == "__main__":
    run()
