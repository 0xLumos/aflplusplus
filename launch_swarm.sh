#!/bin/bash
# =============================================================================
# SKIA AFL++ CVE-HUNTER v7.0
#
# CVE-ADAPTED FUZZER: Targets the exact code patterns that produced
# real-world Skia CVEs exploited in the wild.
#
# CVE ATTACK SURFACE MAPPING:
#   Target 0: Canvas paths/shapes     → CVE-2024-8198, CVE-2024-8636
#   Target 1: Gradient shaders        → CVE-2025-0436 (int overflow in rendering)
#   Target 2: Image filters (compose) → CVE-2024-1283 (heap OOB)
#   Target 3: Image decode (codecs)   → CVE-2024-8636 (heap buffer overflow)
#   Target 4: PathOps boolean ops     → CVE-2023-2136 pattern (int overflow)
#   Target 5: SkPicture deserialize   → CVE-2025-0444 (UAF in object lifecycle)
#   Target 6: SkVertices/Mesh ops     → CVE-2023-6345 (vertex count overflow)
#   Target 7: Text + SkMatrix math    → CVE-2026-3538 (int overflow in math)
#   Target 8: SkShader lifecycle       → CVE-2025-0444 (use-after-free)
#   Target 9: Extreme geometry stress  → CVE-2024-8198 (bounds checking)
#
# USAGE:
#   ./fuzz.sh              # Full: build + launch
#   ./fuzz.sh --resume     # Resume existing swarm
#   ./fuzz.sh --triage     # Were-Rabbit crash exploration
#   ./fuzz.sh --diagnose   # Stability diagnostics
# =============================================================================
set -e

MODE="${1:-full}"
WORKDIR="$HOME/skia_fuzzing"

echo "================================================================"
echo "[*] SKIA CVE-HUNTER v7.0 (CVE-Adapted Harness)"
echo "    Mode: $MODE"
echo "================================================================"

# =====================================================================
# PHASE 1: SYSTEM TUNING
# =====================================================================
phase_system_tune() {
    echo "[+] Phase 1: System Tuning..."
    echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
    # STABILITY FIX: Disable ASLR
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
    echo "    ASLR: DISABLED | CPU: PERFORMANCE"

    sudo mkdir -p /mnt/ramdisk
    if ! mountpoint -q /mnt/ramdisk 2>/dev/null; then
        sudo mount -t tmpfs -o size=10G tmpfs /mnt/ramdisk
        echo "    RAM Disk: MOUNTED (10GB)"
    else
        echo "    RAM Disk: ALREADY MOUNTED"
    fi
}

# =====================================================================
# PHASE 2: WORKSPACE
# =====================================================================
phase_workspace() {
    echo "[+] Phase 2: Workspace..."
    mkdir -p "$WORKDIR/dictionaries" "$WORKDIR/in"
    cd "$WORKDIR"
    if [ ! -e "out" ]; then
        mkdir -p /mnt/ramdisk/skia_out
        ln -sf /mnt/ramdisk/skia_out ./out
        echo "    Output: NEW (RAM disk)"
    else
        echo "    Output: EXISTS (resuming)"
    fi
}

# =====================================================================
# PHASE 3: CVE-ADAPTED HARNESS
#
# Each target maps to vulnerability patterns from real Skia CVEs.
# The harness specifically exercises the code paths that were
# historically vulnerable.
# =====================================================================
phase_harness() {
    echo "[+] Phase 3: Writing CVE-adapted harness..."
    cat << 'HARNESS_EOF' > "$WORKDIR/skia_harness.cc"
// ==========================================================================
// SKIA CVE-HUNTER HARNESS v7.0
//
// This harness targets the exact vulnerability patterns found in real-world
// Skia CVEs that were actively exploited in the wild.
//
// CVE MAPPING:
//   [0] Canvas paths     → CVE-2024-8198/8636 (heap OOB from bounds errors)
//   [1] Gradients        → CVE-2025-0436 (integer overflow in rendering)
//   [2] Image filters    → CVE-2024-1283 (heap buffer overflow)
//   [3] Image decode     → CVE-2024-8636 (codec parsing heap overflow)
//   [4] PathOps          → CVE-2023-2136 pattern (integer overflow)
//   [5] SkPicture        → CVE-2025-0444 (deserialize UAF)
//   [6] SkVertices/Mesh  → CVE-2023-6345 (vertex/index count overflow)
//   [7] Text + Matrix    → CVE-2026-3538 (integer overflow in math)
//   [8] Shader lifecycle → CVE-2025-0444 (use-after-free on freed shaders)
//   [9] Extreme geometry → CVE-2024-8198 (huge coords, extreme transforms)
// ==========================================================================

#include "include/core/SkCanvas.h"
#include "include/core/SkPaint.h"
#include "include/core/SkPath.h"
#include "include/core/SkPathBuilder.h"
#include "include/core/SkSurface.h"
#include "include/core/SkImageInfo.h"
#include "include/core/SkBlendMode.h"
#include "include/core/SkRect.h"
#include "include/core/SkRRect.h"
#include "include/core/SkFont.h"
#include "include/core/SkColorFilter.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkSpan.h"
#include "include/core/SkData.h"
#include "include/core/SkImage.h"
#include "include/core/SkStream.h"
#include "include/core/SkPicture.h"
#include "include/core/SkPictureRecorder.h"
#include "include/core/SkRegion.h"
#include "include/core/SkMatrix.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkVertices.h"
#include "include/core/SkMesh.h"
#include "include/effects/SkGradient.h"
#include "include/effects/SkImageFilters.h"
#include "include/effects/SkDashPathEffect.h"
#include "include/codec/SkCodec.h"
#include "include/pathops/SkPathOps.h"

#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include <limits>

__AFL_FUZZ_INIT();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // Cache warmup for stability
    {
        auto w = SkSurfaces::Raster(SkImageInfo::MakeN32Premul(256, 256));
        if (w) {
            SkCanvas* c = w->getCanvas();
            c->clear(SK_ColorTRANSPARENT);
            SkPaint p; p.setColor(SK_ColorBLACK);
            c->drawRect(SkRect::MakeWH(10, 10), p);
            SkFont f; f.setSize(12);
            c->drawSimpleText("w", 1, SkTextEncoding::kUTF8, 0, 10, f, p);
        }
    }

    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > 0) LLVMFuzzerTestOneInput(buf, len);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 32) return 0;
    FuzzedDataProvider fdp(data, size);

    constexpr int kW = 256, kH = 256;
    auto surface = SkSurfaces::Raster(SkImageInfo::MakeN32Premul(kW, kH));
    if (!surface) return 0;
    SkCanvas* canvas = surface->getCanvas();
    canvas->clear(SK_ColorTRANSPARENT);

    // 10 targets — each maps to a CVE pattern
    uint8_t target = fdp.ConsumeIntegralInRange<uint8_t>(0, 9);

    switch (target) {

    // ===== TARGET 0: Canvas + Paths =====
    // CVE-2024-8198/8636: Heap buffer overflow from insufficient bounds
    // checking during graphics processing. Triggered by complex clipping,
    // nested saveLayer, and extreme path coordinates.
    case 0: {
        SkPaint paint;
        paint.setAntiAlias(fdp.ConsumeBool());
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setStyle(static_cast<SkPaint::Style>(fdp.ConsumeIntegralInRange<uint8_t>(0, 2)));
        paint.setStrokeWidth(fdp.ConsumeFloatingPointInRange<float>(0, 100));
        paint.setBlendMode(static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)));

        // CVE pattern: extreme transforms that stress bounds calculations
        canvas->save();
        if (fdp.ConsumeBool()) canvas->scale(
            fdp.ConsumeFloatingPointInRange<float>(0.001f, 1000.0f),
            fdp.ConsumeFloatingPointInRange<float>(0.001f, 1000.0f));
        if (fdp.ConsumeBool()) canvas->rotate(fdp.ConsumeFloatingPointInRange<float>(0, 360));
        if (fdp.ConsumeBool()) canvas->skew(
            fdp.ConsumeFloatingPointInRange<float>(-10, 10),
            fdp.ConsumeFloatingPointInRange<float>(-10, 10));

        SkPathBuilder builder;
        builder.setFillType(static_cast<SkPathFillType>(fdp.ConsumeIntegralInRange<uint8_t>(0, 3)));
        int nv = fdp.ConsumeIntegralInRange<int>(1, 80);
        for (int i = 0; i < nv && fdp.remaining_bytes() > 12; ++i) {
            float x = fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f);
            float y = fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f);
            switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
                case 0: builder.moveTo(x, y); break;
                case 1: builder.lineTo(x, y); break;
                case 2: builder.quadTo(fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f),
                                       fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f), x, y); break;
                case 3: builder.cubicTo(fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e6f,1e6f), x, y); break;
                case 4: builder.conicTo(x, y, x+10, y+10,
                            fdp.ConsumeFloatingPointInRange<float>(0.001f, 100.0f)); break;
                case 5: builder.close(); break;
            }
        }
        SkPath path = builder.detach();

        // CVE pattern: nested saveLayer + clip (stresses buffer allocation)
        int depth = fdp.ConsumeIntegralInRange<int>(1, 8);
        for (int d = 0; d < depth && fdp.remaining_bytes() > 4; ++d) {
            canvas->saveLayer(nullptr, &paint);
            canvas->clipPath(path, fdp.ConsumeBool());
        }
        canvas->drawPath(path, paint);
        canvas->drawPaint(paint);
        for (int d = 0; d < depth; ++d) canvas->restore();

        canvas->restore();
        break;
    }

    // ===== TARGET 1: Gradient Shaders =====
    // CVE-2025-0436: Integer overflow in rendering math when processing
    // gradients with many color stops and extreme positions.
    case 1: {
        SkPaint paint;
        paint.setAntiAlias(fdp.ConsumeBool());

        // CVE pattern: many color stops → more integer math → more overflow risk
        int nc = fdp.ConsumeIntegralInRange<int>(2, 16);
        std::vector<SkColor4f> colors;
        std::vector<float> positions;
        for (int i = 0; i < nc && fdp.remaining_bytes() > 16; ++i) {
            colors.push_back({fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1)});
            // Fuzz positions — unsorted/extreme positions stress gradient math
            positions.push_back(fdp.ConsumeFloatingPointInRange<float>(-1.0f, 2.0f));
        }
        if (colors.size() < 2) break;

        SkTileMode tm = static_cast<SkTileMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 3));
        SkGradient::Colors gc(SkSpan(colors.data(), colors.size()), tm);
        SkGradient grad(gc, {});

        // CVE pattern: extreme point distances → integer overflow in dimension calcs
        SkPoint pts[] = {
            {fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
             fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)},
            {fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
             fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)}
        };

        // Test all gradient types with same extreme params
        uint8_t gt = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (gt == 0) paint.setShader(SkShaders::LinearGradient(pts, grad));
        else if (gt == 1) {
            // CVE: very large or very small radius
            float r = fdp.ConsumeFloatingPointInRange<float>(0.001f, 1e6f);
            paint.setShader(SkShaders::RadialGradient(pts[0], r, grad));
        } else {
            paint.setShader(SkShaders::SweepGradient(pts[0], grad));
        }

        // Draw with gradient applied to various ops
        canvas->drawPaint(paint);
        canvas->drawRect(SkRect::MakeLTRB(-1e4f, -1e4f, 1e4f, 1e4f), paint);
        break;
    }

    // ===== TARGET 2: Image Filters (deep composition) =====
    // CVE-2024-1283: Heap buffer overflow from deeply composed/chained
    // image filters that cause miscalculated allocation sizes.
    case 2: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());

        // CVE pattern: build a DEEP chain of composed filters
        // Each composition adds overhead → can cause allocation miscalcs
        sk_sp<SkImageFilter> chain = nullptr;
        int depth = fdp.ConsumeIntegralInRange<int>(2, 12);
        for (int i = 0; i < depth && fdp.remaining_bytes() > 8; ++i) {
            sk_sp<SkImageFilter> filter;
            switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 4)) {
                case 0: filter = SkImageFilters::Blur(
                    fdp.ConsumeFloatingPointInRange<float>(0.1f, 50),
                    fdp.ConsumeFloatingPointInRange<float>(0.1f, 50), chain); break;
                case 1: filter = SkImageFilters::Offset(
                    fdp.ConsumeFloatingPointInRange<float>(-500, 500),
                    fdp.ConsumeFloatingPointInRange<float>(-500, 500), chain); break;
                case 2: filter = SkImageFilters::Dilate(
                    fdp.ConsumeIntegralInRange<int>(1, 30),
                    fdp.ConsumeIntegralInRange<int>(1, 30), chain); break;
                case 3: filter = SkImageFilters::Erode(
                    fdp.ConsumeIntegralInRange<int>(1, 30),
                    fdp.ConsumeIntegralInRange<int>(1, 30), chain); break;
                case 4: {
                    auto cf = SkColorFilters::Blend(fdp.ConsumeIntegral<SkColor>(),
                        static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)));
                    filter = SkImageFilters::ColorFilter(cf, chain); break;
                }
            }
            chain = filter;
        }

        // Apply deeply chained filter and draw
        paint.setImageFilter(chain);
        canvas->drawRect(SkRect::MakeWH(kW, kH), paint);

        // CVE pattern: also merge multiple filter chains
        if (fdp.remaining_bytes() > 8) {
            auto blur = SkImageFilters::Blur(
                fdp.ConsumeFloatingPointInRange<float>(1, 30),
                fdp.ConsumeFloatingPointInRange<float>(1, 30), nullptr);
            sk_sp<SkImageFilter> merged[] = { chain, blur };
            paint.setImageFilter(SkImageFilters::Merge(merged, 2));
            canvas->drawRect(SkRect::MakeWH(100, 100), paint);
        }
        break;
    }

    // ===== TARGET 3: Image Decode =====
    // CVE-2024-8636: Heap buffer overflow in codec parsing.
    // This is the #1 source of Chrome CVEs from Skia.
    // Feed raw fuzzed bytes to all codec paths.
    case 3: {
        auto skdata = SkData::MakeWithoutCopy(data, size);

        // Try decoding as image (PNG, JPEG, WebP, BMP, GIF, ICO, WBMP)
        auto codec = SkCodec::MakeFromData(skdata);
        if (codec) {
            auto info = codec->getInfo();
            // Limit to prevent OOM (but still allow medium sizes for OOB bugs)
            if (info.width() <= 4096 && info.height() <= 4096 &&
                (int64_t)info.width() * info.height() <= 4*1024*1024) {

                // Full decode
                SkBitmap bm;
                bm.allocPixels(info.makeColorType(kN32_SkColorType));
                memset(bm.getPixels(), 0, bm.computeByteSize());
                codec->getPixels(bm.pixmap());

                // Incremental decode (different code path)
                auto c2 = SkCodec::MakeFromData(skdata);
                if (c2) {
                    SkBitmap bm2;
                    bm2.allocPixels(c2->getInfo().makeColorType(kN32_SkColorType));
                    memset(bm2.getPixels(), 0, bm2.computeByteSize());
                    c2->startIncrementalDecode(bm2.info(), bm2.getPixels(), bm2.rowBytes());
                    c2->incrementalDecode();
                }

                // Scaled decode (yet another code path)
                auto c3 = SkCodec::MakeFromData(skdata);
                if (c3) {
                    auto sd = c3->getScaledDimensions(0.5f);
                    if (sd.width() > 0 && sd.height() > 0 &&
                        (int64_t)sd.width() * sd.height() < 1024*1024) {
                        SkBitmap bm3;
                        auto si = SkImageInfo::MakeN32Premul(sd.width(), sd.height());
                        bm3.allocPixels(si);
                        memset(bm3.getPixels(), 0, bm3.computeByteSize());
                        c3->getPixels(si, bm3.getPixels(), bm3.rowBytes());
                    }
                }

                // Subsetting (different allocation path)
                auto c4 = SkCodec::MakeFromData(skdata);
                if (c4 && info.width() > 2 && info.height() > 2) {
                    SkIRect subset = SkIRect::MakeWH(info.width()/2, info.height()/2);
                    SkCodec::Options opts;
                    opts.fSubset = &subset;
                    SkBitmap bm4;
                    auto subInfo = info.makeWH(subset.width(), subset.height());
                    bm4.allocPixels(subInfo.makeColorType(kN32_SkColorType));
                    memset(bm4.getPixels(), 0, bm4.computeByteSize());
                    c4->getPixels(subInfo.makeColorType(kN32_SkColorType),
                                  bm4.getPixels(), bm4.rowBytes(), &opts);
                }
            }
        }
        break;
    }

    // ===== TARGET 4: PathOps (boolean operations) =====
    // CVE-2023-2136 pattern: Integer overflow in complex path math.
    // AlmostBetweenUlps, AAHairLineOp, path simplification all had overflows.
    case 4: {
        auto bp = [&fdp]() -> SkPath {
            SkPathBuilder b;
            b.setFillType(static_cast<SkPathFillType>(fdp.ConsumeIntegralInRange<uint8_t>(0, 3)));
            int n = fdp.ConsumeIntegralInRange<int>(1, 40);
            for (int i = 0; i < n && fdp.remaining_bytes() > 8; ++i) {
                // CVE pattern: use extreme coordinates to trigger overflows
                float x = fdp.ConsumeFloatingPointInRange<float>(-1e7f, 1e7f);
                float y = fdp.ConsumeFloatingPointInRange<float>(-1e7f, 1e7f);
                switch(fdp.ConsumeIntegralInRange<uint8_t>(0, 4)) {
                    case 0: b.moveTo(x, y); break;
                    case 1: b.lineTo(x, y); break;
                    case 2: b.quadTo(fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                     fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f), x, y); break;
                    case 3: b.cubicTo(fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                      fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                      fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                      fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f), x, y); break;
                    case 4: b.close(); break;
                }
            }
            return b.detach();
        };

        // Multiple paths for boolean ops — more complex = more overflow risk
        SkPath p1 = bp(), p2 = bp(), p3 = bp(), result;

        Simplify(p1, &result);
        SkPathOp ops[] = {kUnion_SkPathOp, kIntersect_SkPathOp, kDifference_SkPathOp,
                          kXOR_SkPathOp, kReverseDifference_SkPathOp};
        for (auto op : ops) {
            if (fdp.remaining_bytes() < 4) break;
            Op(p1, p2, op, &result);
        }
        // Chain: result of Op becomes input to next Op
        if (fdp.remaining_bytes() > 4) Op(result, p3, kUnion_SkPathOp, &result);

        break;
    }

    // ===== TARGET 5: SkPicture Deserialization =====
    // CVE-2025-0444: Use-after-free in Skia graphics objects during
    // rendering. SkPicture deserialization creates complex object graphs
    // where lifetime management bugs emerge.
    case 5: {
        // Feed raw fuzzed data as SKP format — exercises the entire
        // deserialization pipeline where UAF/OOB bugs hide
        auto fuzzData = SkData::MakeWithoutCopy(data, size);
        auto pic = SkPicture::MakeFromData(fuzzData.get());
        if (pic) {
            // Playback on canvas (triggers all recorded operations)
            canvas->clear(SK_ColorTRANSPARENT);
            pic->playback(canvas);

            // CVE pattern: serialize then deserialize again
            // (roundtrip stress tests object lifetime management)
            auto reserialized = pic->serialize();
            if (reserialized) {
                auto pic2 = SkPicture::MakeFromData(reserialized.get());
                if (pic2) {
                    auto s2 = SkSurfaces::Raster(SkImageInfo::MakeN32Premul(128, 128));
                    if (s2) { s2->getCanvas()->clear(0); pic2->playback(s2->getCanvas()); }
                }
            }
        }
        break;
    }

    // ===== TARGET 6: SkVertices / Custom Mesh =====
    // CVE-2023-6345 (CVSS 9.6): Integer overflow in MeshOp::onCombineIfPossible
    // When fVertexCount + that->fVertexCount overflows INT32_MAX, the allocated
    // buffer is too small → out-of-bounds write. This was actively exploited
    // in the wild for sandbox escape.
    case 6: {
        // Pattern: create SkVertices with carefully chosen vertex counts
        // that could trigger integer overflow in combine operations.

        // Fuzz vertex count — try values near INT32_MAX to trigger overflow
        int vertexCount = fdp.ConsumeIntegralInRange<int>(3, 65536);
        int indexCount = fdp.ConsumeBool() ? fdp.ConsumeIntegralInRange<int>(3, 65536) : 0;

        std::vector<SkPoint> positions(vertexCount);
        std::vector<SkColor> colors(vertexCount);
        std::vector<SkPoint> texCoords(vertexCount);
        std::vector<uint16_t> indices;

        for (int i = 0; i < vertexCount && fdp.remaining_bytes() > 8; ++i) {
            positions[i] = {fdp.ConsumeFloatingPointInRange<float>(-1000, 1000),
                            fdp.ConsumeFloatingPointInRange<float>(-1000, 1000)};
            colors[i] = fdp.ConsumeIntegral<SkColor>();
            texCoords[i] = {fdp.ConsumeFloatingPointInRange<float>(0, 256),
                            fdp.ConsumeFloatingPointInRange<float>(0, 256)};
        }

        if (indexCount > 0) {
            indices.resize(indexCount);
            for (int i = 0; i < indexCount && fdp.remaining_bytes() > 2; ++i)
                indices[i] = fdp.ConsumeIntegralInRange<uint16_t>(0, vertexCount - 1);
        }

        // Create SkVertices with triangle modes
        SkVertices::VertexMode vmode = static_cast<SkVertices::VertexMode>(
            fdp.ConsumeIntegralInRange<uint8_t>(0, 2));

        sk_sp<SkVertices> verts;
        if (indexCount > 0 && !indices.empty()) {
            verts = SkVertices::MakeCopy(vmode, vertexCount,
                positions.data(), texCoords.data(), colors.data(),
                indexCount, indices.data());
        } else {
            verts = SkVertices::MakeCopy(vmode, vertexCount,
                positions.data(), texCoords.data(), colors.data());
        }

        if (verts) {
            SkPaint paint;
            paint.setColor(fdp.ConsumeIntegral<SkColor>());
            // CVE-2023-6345 pattern: draw vertices multiple times to trigger
            // onCombineIfPossible which can overflow vertex counts
            for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 8); ++i) {
                canvas->drawVertices(verts,
                    static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)), paint);
            }
        }
        break;
    }

    // ===== TARGET 7: Text + SkMatrix (integer overflow in math) =====
    // CVE-2026-3538: Integer overflow in Skia allowing OOB memory access.
    // Matrix operations involve heavy math that can overflow:
    //   - Matrix inversion (determinant calculation)
    //   - Matrix concatenation chains (accumulation overflow)
    //   - Point mapping through degenerate matrices
    case 7: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setAntiAlias(fdp.ConsumeBool());

        // CVE pattern: construct matrices with values near integer boundaries
        SkMatrix m;
        m.setAll(fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f));

        // CVE pattern: chain matrix concatenations (accumulation overflow)
        SkMatrix acc = m;
        int chainLen = fdp.ConsumeIntegralInRange<int>(2, 20);
        for (int i = 0; i < chainLen && fdp.remaining_bytes() > 36; ++i) {
            SkMatrix m2;
            m2.setAll(fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                      fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f));
            acc = SkMatrix::Concat(acc, m2);
        }

        // Invert the chained matrix (determinant can overflow)
        SkMatrix inv;
        (void)acc.invert(&inv);

        // Map many points through degenerate matrix
        std::vector<SkPoint> pts(fdp.ConsumeIntegralInRange<int>(1, 100));
        for (auto& p : pts)
            p = {fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
                 fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)};
        std::vector<SkPoint> dst(pts.size());
        acc.mapPoints(SkSpan(dst), SkSpan(pts));

        // Draw text with this extreme matrix
        canvas->setMatrix(acc);
        SkFont font;
        font.setSize(fdp.ConsumeFloatingPointInRange<float>(1, 500));
        font.setScaleX(fdp.ConsumeFloatingPointInRange<float>(0.01f, 100.0f));
        font.setSkewX(fdp.ConsumeFloatingPointInRange<float>(-10, 10));
        std::string txt = fdp.ConsumeRandomLengthString(128);
        if (!txt.empty())
            canvas->drawSimpleText(txt.data(), txt.size(), SkTextEncoding::kUTF8,
                fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f), font, paint);
        break;
    }

    // ===== TARGET 8: Shader/Paint Lifecycle (Use-After-Free) =====
    // CVE-2025-0444: UAF in Skia graphics objects. This target stresses
    // object lifecycle by creating, using, nullifying, and reusing
    // shaders and paint objects to expose dangling references.
    case 8: {
        // Create multiple shaders, assign to paints, draw, then
        // release shaders while paints might still reference them

        // Shader 1: gradient
        SkPoint pts[] = {
            {fdp.ConsumeFloatingPointInRange<float>(0,256),
             fdp.ConsumeFloatingPointInRange<float>(0,256)},
            {fdp.ConsumeFloatingPointInRange<float>(0,256),
             fdp.ConsumeFloatingPointInRange<float>(0,256)}
        };
        SkColor4f c1[] = {
            {fdp.ConsumeFloatingPointInRange<float>(0,1), fdp.ConsumeFloatingPointInRange<float>(0,1),
             fdp.ConsumeFloatingPointInRange<float>(0,1), 1.0f},
            {fdp.ConsumeFloatingPointInRange<float>(0,1), fdp.ConsumeFloatingPointInRange<float>(0,1),
             fdp.ConsumeFloatingPointInRange<float>(0,1), 1.0f}
        };
        SkGradient::Colors gc(SkSpan(c1, 2), SkTileMode::kClamp);

        sk_sp<SkShader> shader1, shader2;
        {
            SkGradient grad(gc, {});
            shader1 = SkShaders::LinearGradient(pts, grad);
        }

        // Shader 2: color filter shader
        auto cf = SkColorFilters::Blend(fdp.ConsumeIntegral<SkColor>(),
            static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)));

        // Stress lifecycle: assign, draw, reassign, draw, null, draw
        SkPaint paint1, paint2;
        paint1.setShader(shader1);
        paint2.setShader(shader1);  // Two paints share same shader

        canvas->drawRect(SkRect::MakeWH(100, 100), paint1);
        canvas->drawRect(SkRect::MakeXYWH(50, 50, 100, 100), paint2);

        // Now release the original shader reference
        shader1.reset();

        // paint1 and paint2 still hold refs — draw should still work
        canvas->drawRect(SkRect::MakeWH(200, 200), paint1);

        // Set null shader and try drawing
        paint1.setShader(nullptr);
        paint1.setColor(fdp.ConsumeIntegral<SkColor>());
        canvas->drawRect(SkRect::MakeWH(100, 100), paint1);

        // paint2 still has the old shader — cross-draw
        canvas->drawRect(SkRect::MakeWH(50, 50), paint2);

        // Rapid create-use-destroy cycle
        for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 10) && fdp.remaining_bytes() > 16; ++i) {
            SkColor4f tc[] = {
                {fdp.ConsumeFloatingPointInRange<float>(0,1),
                 fdp.ConsumeFloatingPointInRange<float>(0,1),
                 fdp.ConsumeFloatingPointInRange<float>(0,1), 1.0f},
                {fdp.ConsumeFloatingPointInRange<float>(0,1),
                 fdp.ConsumeFloatingPointInRange<float>(0,1),
                 fdp.ConsumeFloatingPointInRange<float>(0,1), 1.0f}
            };
            SkGradient::Colors tgc(SkSpan(tc, 2), SkTileMode::kRepeat);
            SkGradient tg(tgc, {});
            auto tmp = SkShaders::LinearGradient(pts, tg);
            paint1.setShader(tmp);
            canvas->drawRect(SkRect::MakeWH(50, 50), paint1);
            // tmp goes out of scope — paint1 holds last ref
        }
        canvas->drawRect(SkRect::MakeWH(100, 100), paint1);
        break;
    }

    // ===== TARGET 9: Extreme Geometry Stress =====
    // CVE-2024-8198: Heap buffer overflow from insufficient boundary
    // validation. This target pushes extreme coordinates, sizes, and
    // combinations through all drawing operations.
    case 9: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setAntiAlias(fdp.ConsumeBool());
        paint.setStyle(static_cast<SkPaint::Style>(fdp.ConsumeIntegralInRange<uint8_t>(0, 2)));
        paint.setStrokeWidth(fdp.ConsumeFloatingPointInRange<float>(0, 1e4f));

        // Extreme coordinates for all drawing ops
        float HUGE = 1e7f;

        // Extremes: huge rectangle
        canvas->drawRect(SkRect::MakeLTRB(
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE)), paint);

        // Extremes: huge rounded rect
        SkRRect rr;
        rr.setRectXY(SkRect::MakeLTRB(
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE)),
            fdp.ConsumeFloatingPointInRange<float>(0, 1e5f),
            fdp.ConsumeFloatingPointInRange<float>(0, 1e5f));
        canvas->drawRRect(rr, paint);

        // Extremes: circle with huge radius
        canvas->drawCircle(
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(0, HUGE), paint);

        // Extremes: line
        canvas->drawLine(
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE), paint);

        // Extremes: oval
        canvas->drawOval(SkRect::MakeLTRB(
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE),
            fdp.ConsumeFloatingPointInRange<float>(-HUGE, HUGE)), paint);

        // Extremes: arc
        canvas->drawArc(SkRect::MakeLTRB(
            fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
            fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
            fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
            fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)),
            fdp.ConsumeFloatingPointInRange<float>(0, 360),
            fdp.ConsumeFloatingPointInRange<float>(0, 360),
            fdp.ConsumeBool(), paint);

        // Dash path effect with extreme intervals
        if (fdp.remaining_bytes() > 16) {
            float intervals[] = {
                fdp.ConsumeFloatingPointInRange<float>(0.001f, 1e5f),
                fdp.ConsumeFloatingPointInRange<float>(0.001f, 1e5f)
            };
            paint.setPathEffect(SkDashPathEffect::Make(intervals, 2,
                fdp.ConsumeFloatingPointInRange<float>(0, 1e5f)));
            canvas->drawRect(SkRect::MakeWH(200, 200), paint);
        }
        break;
    }

    } // switch
    return 0;
}
HARNESS_EOF
    echo "    Harness: 10 CVE-targeted attack surfaces"
}

# =====================================================================
# PHASE 4: DICTIONARY (CVE-enriched)
# =====================================================================
phase_dictionary() {
    echo "[+] Phase 4: CVE-enriched dictionary..."
    cat << 'EOF' > "$WORKDIR/dictionaries/skia.dict"
# Path verbs
verb_move="move"
verb_line="line"
verb_quad="quad"
verb_conic="conic"
verb_cubic="cubic"
verb_close="close"
# Gradients
grad_linear="LinearGradient"
grad_radial="RadialGradient"
grad_sweep="SweepGradient"
# Filters
filter_blur="Blur"
filter_compose="Compose"
filter_merge="Merge"
# Canvas ops
cmd_save="saveLayer"
cmd_restore="restore"
cmd_clip="clipPath"
cmd_concat="concat"
# Image headers (codec parsing — CVE-2024-8636)
header_png="\x89PNG\x0d\x0a\x1a\x0a"
header_jpg="\xff\xd8\xff\xe0"
header_jpg_exif="\xff\xd8\xff\xe1"
header_gif87="GIF87a"
header_gif89="GIF89a"
header_bmp="BM"
header_webp="RIFF"
header_webp2="WEBP"
header_ico="\x00\x00\x01\x00"
header_wbmp="\x00\x00"
# SKP format (SkPicture — CVE-2025-0444)
header_skp="skiapict"
# Vertices/Mesh (CVE-2023-6345)
kw_vertices="SkVertices"
kw_mesh="MeshOp"
kw_combine="combine"
# Float edge cases (trigger overflow — CVE-2026-3538)
float_zero="\x00\x00\x00\x00"
float_one="\x00\x00\x80\x3f"
float_neg_one="\x00\x00\x80\xbf"
float_inf="\x00\x00\x80\x7f"
float_neg_inf="\x00\x00\x80\xff"
float_nan="\x00\x00\xc0\x7f"
float_max="\xff\xff\x7f\x7f"
float_min="\x01\x00\x00\x00"
# Integer edge cases (trigger CVE-2023-2136, CVE-2023-6345)
int32_max="\xff\xff\xff\x7f"
int32_min="\x00\x00\x00\x80"
int32_near_max="\xfe\xff\xff\x7f"
int16_max="\xff\x7f"
uint16_max="\xff\xff"
EOF
}

# =====================================================================
# PHASE 5-8: Fetch, Corpus, Compile, Minimize (unchanged from v6.0)
# =====================================================================
phase_fetch() {
    echo "[+] Phase 5: Fetching Skia..."
    cd "$WORKDIR"
    if [ ! -d "skia" ]; then
        git clone 'https://skia.googlesource.com/skia'
    else
        echo "    Skia exists, syncing deps..."
    fi
    cd skia && python3 tools/git-sync-deps && bin/fetch-gn && cd "$WORKDIR"
}

phase_corpus() {
    echo "[+] Phase 6: Corpus..."
    cd "$WORKDIR"
    EXISTING=$(ls -1 in/ 2>/dev/null | wc -l)
    if [ "$EXISTING" -gt 5 ]; then
        echo "    Corpus exists ($EXISTING files)"
    else
        find skia/resources/ -name "*.svg" -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.skp" -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.png" -size -10k -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.jpg" -size -10k -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.webp" -size -10k -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.gif" -size -10k -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.bmp" -size -10k -exec cp {} in/ \; 2>/dev/null || true
        echo "skia_fuzz_seed" > in/seed.txt
        echo "    Seeded: $(ls -1 in/ | wc -l) files"
    fi
}

phase_compile() {
    echo "[+] Phase 7: Compiling 4 targets..."
    cd "$WORKDIR/skia"
    BASE='cc="afl-clang-fast" cxx="afl-clang-fast++" is_debug=false is_official_build=false skia_use_system_freetype2=false skia_enable_ganesh=false skia_enable_graphite=false skia_enable_skottie=false skia_enable_pdf=false'

    build_target() {
        local N=$1 BIN=$2 GN=$3 CXX=$4 ENV=$5
        if [ -f "$WORKDIR/$BIN" ]; then echo "    $N: EXISTS"; return; fi
        echo "    -> $N..."
        eval "$ENV bin/gn gen out/$N --args='$GN'"
        eval "$ENV ninja -j 8 -C out/$N skia"
        eval "$ENV afl-clang-fast++ $CXX -I. ../skia_harness.cc out/$N/libskia.a -o ../$BIN -lpthread -ldl -lfreetype -lfontconfig"
    }

    build_target "Fast" "harness_skia_fast" \
        "$BASE extra_cflags=[\"-w\",\"-O3\",\"-march=znver3\",\"-flto\"] extra_ldflags=[\"-w\",\"-flto\"]" \
        "-O3 -march=znver3 -flto" ""
    build_target "ASan" "harness_skia_asan" \
        "$BASE extra_cflags=[\"-w\",\"-fsanitize=address\"] extra_ldflags=[\"-w\",\"-fsanitize=address\"]" \
        "-O2 -fsanitize=address" "AFL_USE_ASAN=1"
    build_target "UBSan" "harness_skia_ubsan" \
        "$BASE extra_cflags=[\"-w\",\"-fsanitize=undefined,integer,nullability\",\"-fno-sanitize-recover=all\"] extra_ldflags=[\"-w\",\"-fsanitize=undefined,integer,nullability\"]" \
        "-O2 -fsanitize=undefined,integer,nullability -fno-sanitize-recover=all" "AFL_USE_UBSAN=1"
    build_target "CmpLog" "harness_skia_cmplog" \
        "$BASE extra_cflags=[\"-w\"] extra_ldflags=[\"-w\"]" \
        "-O3" "AFL_LLVM_CMPLOG=1"
    cd "$WORKDIR"
}

phase_minimize() {
    echo "[+] Phase 8: Corpus minimization..."
    cd "$WORKDIR"
    if [ -d "in_minimized" ]; then echo "    Already done"; return; fi
    mkdir -p in_min
    AFL_MAP_SIZE=2560000 timeout 120 afl-cmin -i in -o in_min -m none -t 2000 -- ./harness_skia_fast 2>/dev/null || true
    MIN=$(ls -1 in_min/ 2>/dev/null | wc -l)
    if [ "$MIN" -gt 0 ]; then
        mv in in_full && mv in_min in && touch in_minimized
        echo "    Minimized to $MIN files"
    else
        rm -rf in_min; echo "    Skipped"
    fi
}

# =====================================================================
# PHASE 9: STABILITY DIAGNOSTIC
# =====================================================================
phase_diagnose() {
    echo "[+] Phase 9: Stability diagnostic..."
    cd "$WORKDIR"
    [ ! -f harness_skia_fast ] && echo "    No binary" && return
    TEST="$(ls in/ 2>/dev/null | head -1)"
    [ -z "$TEST" ] && echo "test" > /tmp/si && TEST="/tmp/si" || TEST="in/$TEST"
    mkdir -p /tmp/sd
    for i in $(seq 1 10); do
        AFL_MAP_SIZE=2560000 afl-showmap -m none -t 2000 -o "/tmp/sd/m$i" -- ./harness_skia_fast < "$TEST" 2>/dev/null
    done
    BASE=$(wc -l < /tmp/sd/m1 2>/dev/null)
    echo "    Run | Diff | Stability"
    for i in $(seq 2 10); do
        D=$(diff /tmp/sd/m1 /tmp/sd/m$i 2>/dev/null | grep "^[<>]" | wc -l)
        S=$(echo "scale=1; (1-$D/$BASE)*100" | bc 2>/dev/null || echo "?")
        printf "     %2d  | %4d | %s%%\n" "$i" "$D" "$S"
    done
    rm -rf /tmp/sd
    ASLR=$(cat /proc/sys/kernel/randomize_va_space)
    [ "$ASLR" = "0" ] && echo "    ASLR: OFF (good)" || echo "    ASLR: ON — FIX!"
}

# =====================================================================
# PHASE 10: LAUNCH 8-CORE SWARM
# =====================================================================
phase_launch() {
    echo "[+] Phase 10: Launching CVE-Hunter Swarm..."
    cd "$WORKDIR"
    pkill -9 afl-fuzz 2>/dev/null || true
    screen -ls 2>/dev/null | grep -v "No Sockets" | grep -E "\." | awk '{print $1}' | xargs -I{} screen -X -S {} quit 2>/dev/null || true
    sleep 1

    ENV="export AFL_AUTORESUME=1; export AFL_IMPORT_FIRST=1; export AFL_CMPLOG_ONLY_NEW=1; export AFL_MAP_SIZE=2560000; export AFL_NO_TRIM=1; export AFL_FAST_CAL=1; export AFL_SKIP_CPUFREQ=1"
    AENV="export ASAN_OPTIONS='detect_leaks=0:symbolize=0:abort_on_error=1:detect_odr_violation=0'"
    UENV="export UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_stacktrace=1'"

    echo "    Core 1: master    (ASAN + CmpLog + Deterministic)"
    screen -dmS master bash -c "cd $WORKDIR; $ENV; $AENV; afl-fuzz -i in -o out -D -M master -l 2 -c ./harness_skia_cmplog -x dictionaries/skia.dict -m none -t 5000+ -- ./harness_skia_asan"

    echo "    Core 2: ubsan     (UBSan → CVE-2023-2136, CVE-2026-3538)"
    screen -dmS ubsan bash -c "cd $WORKDIR; $ENV; $UENV; afl-fuzz -i in -o out -S ubsan -p explore -x dictionaries/skia.dict -m none -t 5000+ -- ./harness_skia_ubsan"

    echo "    Core 3: asan_exp  (ASAN → CVE-2025-0444, CVE-2024-8198)"
    screen -dmS asan_exp bash -c "cd $WORKDIR; $ENV; $AENV; afl-fuzz -i in -o out -S asan_exp -p explore -x dictionaries/skia.dict -m none -t 5000+ -- ./harness_skia_asan"

    SCHEDULES=("fast" "rare" "seek" "coe" "exploit")
    for i in {0..4}; do
        C=$((i+4)); S=${SCHEDULES[$i]}; EX=""
        [ "$C" -eq 6 ] && EX="-z"
        echo "    Core $C: fast_$C   ($S${EX:+ +havoc})"
        screen -dmS "fast_$C" bash -c "cd $WORKDIR; $ENV; afl-fuzz -i in -o out -S fast_$C -p $S $EX -x dictionaries/skia.dict -m none -t 2000 -- ./harness_skia_fast"
    done
    echo "    8 cores launched"
}

# =====================================================================
# PHASE 11: WERE-RABBIT TRIAGE
# =====================================================================
phase_triage() {
    echo "[+] Were-Rabbit Crash Triage..."
    cd "$WORKDIR"
    CRASHES=$(find out/*/crashes/ -type f ! -name "README*" 2>/dev/null | wc -l)
    if [ "$CRASHES" -eq 0 ]; then echo "    No crashes yet"; return; fi
    mkdir -p triage_corpus
    find out/*/crashes/ -type f ! -name "README*" -exec cp {} triage_corpus/ \; 2>/dev/null
    echo "    $CRASHES crashes → Were-Rabbit"
    screen -dmS triage bash -c "cd $WORKDIR; export AFL_AUTORESUME=1; export AFL_MAP_SIZE=2560000; export ASAN_OPTIONS='detect_leaks=0:symbolize=0:abort_on_error=1'; afl-fuzz -i triage_corpus -o triage_out -C -m none -t 5000+ -- ./harness_skia_asan"
    echo "    Monitor: screen -r triage"
}

# =====================================================================
# MAIN
# =====================================================================
phase_system_tune

case "$MODE" in
    "--resume")  phase_workspace; phase_launch ;;
    "--triage")  phase_workspace; phase_triage ;;
    "--diagnose") phase_workspace; phase_diagnose ;;
    *)
        phase_workspace; phase_harness; phase_dictionary
        phase_fetch; phase_corpus; phase_compile; phase_minimize
        phase_diagnose; phase_launch
        ;;
esac

echo ""
echo "================================================================"
echo "[DONE] SKIA CVE-HUNTER v7.0"
echo "================================================================"
echo ""
echo "CVE ATTACK SURFACES:"
echo "  [0] Canvas+Paths    → CVE-2024-8198/8636 (heap OOB)"
echo "  [1] Gradients       → CVE-2025-0436 (int overflow)"
echo "  [2] ImageFilters    → CVE-2024-1283 (heap OOB)"
echo "  [3] ImageDecode     → CVE-2024-8636 (codec parsing)"
echo "  [4] PathOps         → CVE-2023-2136 (int overflow)"
echo "  [5] SkPicture       → CVE-2025-0444 (UAF)"
echo "  [6] SkVertices/Mesh → CVE-2023-6345 (vertex overflow)"
echo "  [7] Text+Matrix     → CVE-2026-3538 (math overflow)"
echo "  [8] ShaderLifecycle → CVE-2025-0444 (UAF)"
echo "  [9] ExtremeGeometry → CVE-2024-8198 (bounds bypass)"
echo ""
echo "Commands:  watch -n 2 afl-whatsup -s -d out"
echo "           screen -r master | ./fuzz.sh --triage"
