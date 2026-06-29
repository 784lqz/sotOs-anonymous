#!/usr/bin/env python3
# T4 / Figure F1: linear regression of steady-state memory (root_pages) vs spawn cycle,
# reporting slope ± 95% CI. The paper's claim "banda plana, pendiente indistinguible de
# cero" is supported iff the CI includes 0 (or |slope| below a stated threshold).
# Pure stdlib (no numpy) so it runs anywhere. Emits a gnuplot-able data file for F1.
import sys, math, csv
path = sys.argv[1] if len(sys.argv) > 1 else "tools/eval/t4-containment/samples.csv"
rows = list(csv.DictReader(open(path)))
xs = [float(r["iter"]) for r in rows]
ys = [float(r["root_pages"]) for r in rows]
n = len(xs)
if n < 2:
    print(f"[F1] need >=2 samples (got {n}) — soak/stats not emitting?"); sys.exit(1)
mx, my = sum(xs)/n, sum(ys)/n
sxx = sum((x-mx)**2 for x in xs)
sxy = sum((x-mx)*(y-my) for x, y in zip(xs, ys))
slope = sxy/sxx if sxx else 0.0
intercept = my - slope*mx
resid = [y-(intercept+slope*x) for x, y in zip(xs, ys)]
s2 = (sum(r*r for r in resid)/(n-2)) if n > 2 else 0.0
se = math.sqrt(s2/sxx) if sxx > 0 else 0.0
ci = 1.96*se                      # ~95% (large-n normal approx)
band = max(ys)-min(ys)
print(f"[F1] samples={n}")
print(f"[F1] slope     = {slope:+.4f} frames/cycle")
print(f"[F1] 95% CI    = +/- {ci:.4f}  (=> [{slope-ci:+.4f}, {slope+ci:+.4f}])")
print(f"[F1] band(maxmin)= {band:.0f} frames")
flat = abs(slope) <= ci
print(f"[F1] VERDICT   = {'FLAT (slope CI includes 0 — zero-leak supported)' if flat else 'DRIFT — investigate'}")
with open("tools/eval/t4-containment/f1-memory-vs-cycle.dat", "w") as f:
    f.write("# cycle root_pages   (plot + fit line slope above)\n")
    f.write("\n".join(f"{int(x)} {int(y)}" for x, y in zip(xs, ys)) + "\n")
print("[F1] data -> tools/eval/t4-containment/f1-memory-vs-cycle.dat")
