#!/bin/bash
# =============================================================================
# SKIA AFL++ FUZZER v8.0
#
# Methodology-driven harness with:
#   - 12 vulnerability pattern targets (including font parsing)
#   - Autodictionary extraction at compile time
#   - Robust screen session management
#   - Automatic crash backup
#   - 100% stability (verified)
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
echo "[*] SKIA FUZZER v8.0"
echo "    Mode: $MODE"
echo "================================================================"

# =====================================================================
# PHASE 1: SYSTEM TUNING
# =====================================================================
phase_system_tune() {
    echo "[+] Phase 1: System Tuning..."
    echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
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
    mkdir -p "$WORKDIR/dictionaries" "$WORKDIR/in" "$WORKDIR/confirmed_crashes"
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
# PHASE 3: HARNESS (12 targets)
# =====================================================================
phase_harness() {
    echo "[+] Phase 3: Writing harness..."
    cat << 'HARNESS_EOF' > "$WORKDIR/skia_harness.cc"
// Skia Fuzz Harness v8.0 — 12 methodology-driven targets
//
// Vulnerability patterns targeted:
//   [0]  Extreme path rendering     — rasterizer integer overflow
//   [1]  Gradient stress            — interpolation math overflow
//   [2]  Deep filter chains         — allocation size miscalculation
//   [3]  Codec multi-path decode    — parser state machine edge cases
//   [4]  Repeated draw accumulation — internal counter overflow
//   [5]  SkPicture round-trip       — deserialization lifecycle issues
//   [6]  SkVertices repetition      — vertex count accumulation overflow
//   [7]  Degenerate matrix chains   — transform pipeline math overflow
//   [8]  Object lifecycle stress    — refcount/dangling reference edges
//   [9]  Nested clip+layer stack    — layer bounds allocation errors
//   [10] Font parsing from data     — font table parsing + glyph raster
//   [11] Convexity confusion        — nearly-convex paths drawn as convex

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
#include "include/core/SkTypeface.h"
#include "include/core/SkFontMgr.h"
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
#include "include/core/SkTextBlob.h"
#include "include/effects/SkGradient.h"
#include "include/effects/SkImageFilters.h"
#include "include/effects/SkDashPathEffect.h"
#include "include/codec/SkCodec.h"

#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>

__AFL_FUZZ_INIT();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // Cache warmup — do once so iteration 1 == iteration N
    {
        auto w = SkSurfaces::Raster(SkImageInfo::MakeN32Premul(256, 256));
        if (w) {
            SkCanvas* c = w->getCanvas();
            c->clear(SK_ColorTRANSPARENT);
            SkPaint p; p.setColor(SK_ColorBLACK);
            c->drawRect(SkRect::MakeWH(10, 10), p);
            SkFont f; f.setSize(12);
            c->drawSimpleText("warmup", 6, SkTextEncoding::kUTF8, 0, 10, f, p);
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

    uint8_t target = fdp.ConsumeIntegralInRange<uint8_t>(0, 11);

    switch (target) {

    // [0] EXTREME PATH RENDERING
    case 0: {
        SkPaint paint;
        paint.setAntiAlias(fdp.ConsumeBool());
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setStyle(static_cast<SkPaint::Style>(fdp.ConsumeIntegralInRange<uint8_t>(0, 2)));
        paint.setStrokeWidth(fdp.ConsumeFloatingPointInRange<float>(0, 1e4f));

        canvas->save();
        if (fdp.ConsumeBool()) canvas->scale(
            fdp.ConsumeFloatingPointInRange<float>(0.001f, 1000.0f),
            fdp.ConsumeFloatingPointInRange<float>(0.001f, 1000.0f));
        if (fdp.ConsumeBool()) canvas->rotate(fdp.ConsumeFloatingPointInRange<float>(0, 360));

        SkPathBuilder builder;
        builder.setFillType(static_cast<SkPathFillType>(fdp.ConsumeIntegralInRange<uint8_t>(0, 3)));
        int nv = fdp.ConsumeIntegralInRange<int>(1, 80);
        for (int i = 0; i < nv && fdp.remaining_bytes() > 12; ++i) {
            float x = fdp.ConsumeFloatingPointInRange<float>(-1e7f, 1e7f);
            float y = fdp.ConsumeFloatingPointInRange<float>(-1e7f, 1e7f);
            switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
                case 0: builder.moveTo(x, y); break;
                case 1: builder.lineTo(x, y); break;
                case 2: builder.quadTo(fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                       fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f), x, y); break;
                case 3: builder.cubicTo(fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f),
                                        fdp.ConsumeFloatingPointInRange<float>(-1e7f,1e7f), x, y); break;
                case 4: builder.conicTo(x, y, x+10, y+10,
                            fdp.ConsumeFloatingPointInRange<float>(0.001f, 100.0f)); break;
                case 5: builder.close(); break;
            }
        }
        SkPath path = builder.detach();
        canvas->drawPath(path, paint);
        canvas->save();
        canvas->clipPath(path, fdp.ConsumeBool());
        canvas->drawPaint(paint);
        canvas->restore();
        canvas->restore();
        break;
    }

    // [1] GRADIENT STRESS
    case 1: {
        SkPaint paint;
        int nc = fdp.ConsumeIntegralInRange<int>(2, 16);
        std::vector<SkColor4f> colors;
        for (int i = 0; i < nc && fdp.remaining_bytes() > 16; ++i)
            colors.push_back({fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1),
                              fdp.ConsumeFloatingPointInRange<float>(0,1)});
        if (colors.size() < 2) break;
        SkTileMode tm = static_cast<SkTileMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 3));
        SkGradient::Colors gc(SkSpan(colors.data(), colors.size()), tm);
        SkGradient grad(gc, {});
        SkPoint pts[] = {
            {fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
             fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)},
            {fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f),
             fdp.ConsumeFloatingPointInRange<float>(-1e5f, 1e5f)}
        };
        uint8_t gt = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (gt == 0) paint.setShader(SkShaders::LinearGradient(pts, grad));
        else if (gt == 1) paint.setShader(SkShaders::RadialGradient(pts[0],
            fdp.ConsumeFloatingPointInRange<float>(0.001f, 1e6f), grad));
        else paint.setShader(SkShaders::SweepGradient(pts[0], grad));
        canvas->drawPaint(paint);
        break;
    }

    // [2] DEEP FILTER CHAINS
    case 2: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
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
        paint.setImageFilter(chain);
        canvas->drawRect(SkRect::MakeWH(kW, kH), paint);
        break;
    }

    // [3] CODEC MULTI-PATH DECODE
    case 3: {
        auto skdata = SkData::MakeWithoutCopy(data, size);
        auto codec = SkCodec::MakeFromData(skdata);
        if (codec) {
            auto info = codec->getInfo();
            if (info.width() <= 4096 && info.height() <= 4096 &&
                (int64_t)info.width() * info.height() <= 4*1024*1024) {
                SkBitmap bm;
                bm.allocPixels(info.makeColorType(kN32_SkColorType));
                memset(bm.getPixels(), 0, bm.computeByteSize());
                codec->getPixels(bm.pixmap());

                auto c2 = SkCodec::MakeFromData(skdata);
                if (c2) {
                    SkBitmap bm2;
                    bm2.allocPixels(c2->getInfo().makeColorType(kN32_SkColorType));
                    memset(bm2.getPixels(), 0, bm2.computeByteSize());
                    c2->startIncrementalDecode(bm2.info(), bm2.getPixels(), bm2.rowBytes());
                    c2->incrementalDecode();
                }

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
            }
        }
        break;
    }

    // [4] REPEATED DRAW ACCUMULATION
    case 4: {
        SkPaint paint;
        paint.setAntiAlias(fdp.ConsumeBool());
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setStyle(static_cast<SkPaint::Style>(fdp.ConsumeIntegralInRange<uint8_t>(0, 2)));
        int reps = fdp.ConsumeIntegralInRange<int>(50, 500);
        for (int i = 0; i < reps && fdp.remaining_bytes() > 4; ++i) {
            float x = fdp.ConsumeFloatingPointInRange<float>(-500, 500);
            float y = fdp.ConsumeFloatingPointInRange<float>(-500, 500);
            canvas->drawRect(SkRect::MakeXYWH(x, y,
                fdp.ConsumeFloatingPointInRange<float>(1, 200),
                fdp.ConsumeFloatingPointInRange<float>(1, 200)), paint);
        }
        break;
    }

    // [5] SkPicture ROUND-TRIP
    case 5: {
        auto fuzzData = SkData::MakeWithoutCopy(data, size);
        auto pic = SkPicture::MakeFromData(fuzzData.get());
        if (pic) {
            pic->playback(canvas);
            auto re = pic->serialize();
            if (re) {
                auto p2 = SkPicture::MakeFromData(re.get());
                if (p2) {
                    auto s2 = SkSurfaces::Raster(SkImageInfo::MakeN32Premul(128, 128));
                    if (s2) { s2->getCanvas()->clear(0); p2->playback(s2->getCanvas()); }
                }
            }
        }
        break;
    }

    // [6] SkVertices REPETITION  *** Found NULL deref here in v7.0! ***
    case 6: {
        int vc = fdp.ConsumeIntegralInRange<int>(3, 2048);
        std::vector<SkPoint> pos(vc);
        std::vector<SkColor> col(vc);
        for (int i = 0; i < vc && fdp.remaining_bytes() > 8; ++i) {
            pos[i] = {fdp.ConsumeFloatingPointInRange<float>(-500, 500),
                       fdp.ConsumeFloatingPointInRange<float>(-500, 500)};
            col[i] = fdp.ConsumeIntegral<SkColor>();
        }
        auto vmode = static_cast<SkVertices::VertexMode>(
            fdp.ConsumeIntegralInRange<uint8_t>(0, 2));
        auto verts = SkVertices::MakeCopy(vmode, vc, pos.data(), nullptr, col.data());
        if (verts) {
            SkPaint paint;
            paint.setColor(fdp.ConsumeIntegral<SkColor>());
            int reps = fdp.ConsumeIntegralInRange<int>(10, 200);
            for (int i = 0; i < reps; ++i)
                canvas->drawVertices(verts,
                    static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)), paint);
        }
        break;
    }

    // [7] DEGENERATE MATRIX CHAINS
    case 7: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        SkMatrix acc;
        acc.setAll(fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f),
                   fdp.ConsumeFloatingPointInRange<float>(-1e6f, 1e6f));
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
        SkMatrix inv;
        (void)acc.invert(&inv);
        canvas->setMatrix(acc);
        SkFont font;
        font.setSize(fdp.ConsumeFloatingPointInRange<float>(1, 500));
        std::string txt = fdp.ConsumeRandomLengthString(128);
        if (!txt.empty())
            canvas->drawSimpleText(txt.data(), txt.size(), SkTextEncoding::kUTF8,
                fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f),
                fdp.ConsumeFloatingPointInRange<float>(-1e4f, 1e4f), font, paint);
        break;
    }

    // [8] OBJECT LIFECYCLE STRESS
    case 8: {
        SkPoint pts[] = {{0,0},{256,256}};
        SkColor4f c1[] = {{1,0,0,1},{0,0,1,1}};
        SkGradient::Colors gc(SkSpan(c1, 2), SkTileMode::kClamp);
        sk_sp<SkShader> shader1;
        { SkGradient g(gc, {}); shader1 = SkShaders::LinearGradient(pts, g); }
        SkPaint p1, p2;
        p1.setShader(shader1); p2.setShader(shader1);
        canvas->drawRect(SkRect::MakeWH(100, 100), p1);
        shader1.reset();
        canvas->drawRect(SkRect::MakeWH(200, 200), p1);
        p1.setShader(nullptr);
        p1.setColor(fdp.ConsumeIntegral<SkColor>());
        canvas->drawRect(SkRect::MakeWH(100, 100), p1);
        canvas->drawRect(SkRect::MakeWH(50, 50), p2);
        for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 20) && fdp.remaining_bytes() > 16; ++i) {
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
            p1.setShader(tmp);
            canvas->drawRect(SkRect::MakeWH(50, 50), p1);
        }
        break;
    }

    // [9] NESTED CLIP + LAYER STACK
    case 9: {
        SkPaint paint;
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        int depth = fdp.ConsumeIntegralInRange<int>(3, 15);
        for (int d = 0; d < depth && fdp.remaining_bytes() > 20; ++d) {
            SkPaint lp;
            lp.setAlphaf(fdp.ConsumeFloatingPointInRange<float>(0.1f, 1.0f));
            lp.setBlendMode(static_cast<SkBlendMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, 29)));
            canvas->saveLayer(nullptr, &lp);
            if (fdp.ConsumeBool()) {
                canvas->clipRect(SkRect::MakeLTRB(
                    fdp.ConsumeFloatingPointInRange<float>(-200, 200),
                    fdp.ConsumeFloatingPointInRange<float>(-200, 200),
                    fdp.ConsumeFloatingPointInRange<float>(-200, 400),
                    fdp.ConsumeFloatingPointInRange<float>(-200, 400)));
            } else {
                SkPathBuilder cb;
                cb.moveTo(fdp.ConsumeFloatingPointInRange<float>(-200,200),
                          fdp.ConsumeFloatingPointInRange<float>(-200,200));
                cb.lineTo(fdp.ConsumeFloatingPointInRange<float>(-200,200),
                          fdp.ConsumeFloatingPointInRange<float>(-200,200));
                cb.lineTo(fdp.ConsumeFloatingPointInRange<float>(-200,200),
                          fdp.ConsumeFloatingPointInRange<float>(-200,200));
                cb.close();
                canvas->clipPath(cb.detach(), fdp.ConsumeBool());
            }
            paint.setColor(fdp.ConsumeIntegral<SkColor>());
            canvas->drawRect(SkRect::MakeWH(
                fdp.ConsumeFloatingPointInRange<float>(10, 300),
                fdp.ConsumeFloatingPointInRange<float>(10, 300)), paint);
        }
        for (int d = 0; d < depth; ++d) canvas->restore();
        break;
    }

    // [10] FONT PARSING FROM FUZZED DATA
    // Feed raw bytes as TTF/OTF → exercises font table parsing, glyph
    // rasterization, hinting, complex text shaping. Historically one of
    // the highest-yield attack surfaces (BrokenType found 100s of bugs).
    case 10: {
        auto fontData = SkData::MakeWithoutCopy(data, size);
        auto stream = SkMemoryStream::Make(fontData);
        auto typeface = SkTypeface::MakeFromStream(std::move(stream));
        if (typeface) {
            SkFont font(typeface);
            font.setSize(fdp.ConsumeFloatingPointInRange<float>(1, 200));
            font.setScaleX(fdp.ConsumeFloatingPointInRange<float>(0.1f, 10.0f));
            font.setSkewX(fdp.ConsumeFloatingPointInRange<float>(-5, 5));

            SkPaint paint;
            paint.setColor(fdp.ConsumeIntegral<SkColor>());
            paint.setAntiAlias(fdp.ConsumeBool());

            // Draw various strings to exercise different glyph paths
            const char* strs[] = {"ABCDEFGHIJ", "0123456789", "!@#$%^&*()",
                                  "\xC3\xA9\xC3\xB1\xC3\xBC", "WwMmIi"};
            for (int i = 0; i < 5; ++i) {
                canvas->drawSimpleText(strs[i], strlen(strs[i]), SkTextEncoding::kUTF8,
                    fdp.ConsumeFloatingPointInRange<float>(-100, 300),
                    fdp.ConsumeFloatingPointInRange<float>(-100, 300), font, paint);
            }

            // Also measure text (different code path)
            SkRect bounds;
            font.measureText("ABCDEF", 6, SkTextEncoding::kUTF8, &bounds);

            // Get glyph IDs (exercises cmap table parsing)
            SkGlyphID glyphs[10];
            font.textToGlyphs("ABCDEFGHIJ", 10, SkTextEncoding::kUTF8, glyphs, 10);

            // Draw with different sizes to stress glyph cache
            for (int sz = 8; sz <= 72 && fdp.remaining_bytes() > 4; sz += 8) {
                font.setSize(sz);
                canvas->drawSimpleText("Ag", 2, SkTextEncoding::kUTF8,
                    10, (float)sz, font, paint);
            }
        }
        break;
    }

    // [11] CONVEXITY CONFUSION
    // Build paths that are *nearly* convex — a single segment that barely
    // makes the path concave. If Skia misidentifies this as convex, it
    // uses a fast convex-only algorithm that doesn't handle concave edges,
    // leading to memory corruption. (Google Project Zero technique)
    case 11: {
        SkPaint paint;
        paint.setAntiAlias(fdp.ConsumeBool());
        paint.setColor(fdp.ConsumeIntegral<SkColor>());
        paint.setStyle(static_cast<SkPaint::Style>(fdp.ConsumeIntegralInRange<uint8_t>(0, 2)));

        for (int p = 0; p < fdp.ConsumeIntegralInRange<int>(1, 10) && fdp.remaining_bytes() > 16; ++p) {
            SkPathBuilder b;
            // Start with a convex shape
            float cx = fdp.ConsumeFloatingPointInRange<float>(50, 200);
            float cy = fdp.ConsumeFloatingPointInRange<float>(50, 200);
            float r = fdp.ConsumeFloatingPointInRange<float>(10, 100);
            int sides = fdp.ConsumeIntegralInRange<int>(3, 20);

            b.moveTo(cx + r, cy);
            for (int i = 1; i < sides; ++i) {
                float angle = (float)i * 6.283185f / (float)sides;
                float pr = r;
                // Occasionally make ONE vertex slightly concave
                if (i == sides / 2)
                    pr = r * fdp.ConsumeFloatingPointInRange<float>(0.5f, 1.5f);
                b.lineTo(cx + pr * cosf(angle), cy + pr * sinf(angle));
            }
            b.close();

            SkPath path = b.detach();

            // Force Skia to compute convexity then draw
            (void)path.isConvex();
            canvas->drawPath(path, paint);

            // Also draw filled + stroked (different render paths)
            paint.setStyle(SkPaint::kFill_Style);
            canvas->drawPath(path, paint);
            paint.setStyle(SkPaint::kStroke_Style);
            paint.setStrokeWidth(fdp.ConsumeFloatingPointInRange<float>(0.5f, 20.0f));
            canvas->drawPath(path, paint);
        }
        break;
    }

    } // switch
    return 0;
}
HARNESS_EOF
    echo "    Harness: 12 targets (+ font parsing + convexity confusion)"
}

# =====================================================================
# PHASE 4: DICTIONARY
# =====================================================================
phase_dictionary() {
    echo "[+] Phase 4: Dictionary..."
    cat << 'EOF' > "$WORKDIR/dictionaries/skia.dict"
verb_move="move"
verb_line="line"
verb_quad="quad"
verb_cubic="cubic"
verb_close="close"
grad_linear="LinearGradient"
grad_radial="RadialGradient"
filter_blur="Blur"
cmd_save="saveLayer"
cmd_restore="restore"
cmd_clip="clipPath"
header_png="\x89PNG\x0d\x0a\x1a\x0a"
header_jpg="\xff\xd8\xff\xe0"
header_gif89="GIF89a"
header_bmp="BM"
header_webp="RIFF"
header_ico="\x00\x00\x01\x00"
header_skp="skiapict"
header_ttf="\x00\x01\x00\x00"
header_otf="OTTO"
header_ttc="ttcf"
header_woff="wOFF"
header_woff2="wOF2"
float_zero="\x00\x00\x00\x00"
float_one="\x00\x00\x80\x3f"
float_inf="\x00\x00\x80\x7f"
float_nan="\x00\x00\xc0\x7f"
float_max="\xff\xff\x7f\x7f"
int32_max="\xff\xff\xff\x7f"
int32_min="\x00\x00\x00\x80"
uint16_max="\xff\xff"
EOF
    echo "    Dict: skia.dict (+ font headers TTF/OTF/WOFF)"
}

# =====================================================================
# PHASE 5-8: Fetch, Corpus, Compile, Minimize
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
        find skia/resources/ -name "*.ttf" -size -50k -exec cp {} in/ \; 2>/dev/null || true
        find skia/resources/ -name "*.otf" -size -50k -exec cp {} in/ \; 2>/dev/null || true
        echo "skia_fuzz_seed" > in/seed.txt
        echo "    Seeded: $(ls -1 in/ | wc -l) files (images + fonts)"
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
        eval "$ENV ninja -j$(nproc) -C out/$N skia"
        eval "$ENV afl-clang-fast++ $CXX -I. ../skia_harness.cc out/$N/libskia.a -o ../$BIN -lpthread -ldl -lfreetype -lfontconfig"
    }

    build_target "Fast" "harness_skia_fast" \
        "$BASE extra_cflags=[\"-w\",\"-O3\",\"-march=native\",\"-flto\"] extra_ldflags=[\"-w\",\"-flto\"]" \
        "-O3 -march=native -flto" ""
    build_target "ASan" "harness_skia_asan" \
        "$BASE extra_cflags=[\"-w\",\"-fsanitize=address\"] extra_ldflags=[\"-w\",\"-fsanitize=address\"]" \
        "-O2 -fsanitize=address" "AFL_USE_ASAN=1"
    build_target "UBSan" "harness_skia_ubsan" \
        "$BASE extra_cflags=[\"-w\",\"-fsanitize=undefined,integer\",\"-fsanitize-recover=all\"] extra_ldflags=[\"-w\",\"-fsanitize=undefined,integer\"]" \
        "-O2 -fsanitize=undefined,integer -fsanitize-recover=all" "AFL_USE_UBSAN=1"
    build_target "CmpLog" "harness_skia_cmplog" \
        "$BASE extra_cflags=[\"-w\"] extra_ldflags=[\"-w\"]" \
        "-O3" "AFL_LLVM_CMPLOG=1"

    # Autodictionary extraction (free tokens from binary constants)
    if [ ! -f "$WORKDIR/dictionaries/auto_skia.dict" ]; then
        echo "    -> Extracting autodictionary..."
        AFL_LLVM_DICT2FILE="$WORKDIR/dictionaries/auto_skia.dict" \
            afl-clang-fast++ -O3 -I. ../skia_harness.cc out/Fast/libskia.a \
            -o /dev/null -lpthread -ldl -lfreetype -lfontconfig 2>/dev/null || true
        if [ -f "$WORKDIR/dictionaries/auto_skia.dict" ]; then
            echo "    Autodict: $(wc -l < $WORKDIR/dictionaries/auto_skia.dict) tokens extracted"
        fi
    fi

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
        rm -rf in_full 2>/dev/null || true
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
# PHASE 10: BACKUP CRASHES + LAUNCH 8-CORE SWARM
# =====================================================================
phase_backup_crashes() {
    cd "$WORKDIR"
    CRASH_COUNT=$(find out/*/crashes/ -type f ! -name "README*" 2>/dev/null | wc -l)
    if [ "$CRASH_COUNT" -gt 0 ]; then
        echo "[+] Backing up $CRASH_COUNT crashes..."
        BACKUP="confirmed_crashes/backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP"
        find out/*/crashes/ -type f ! -name "README*" -exec cp {} "$BACKUP/" \; 2>/dev/null
        echo "    Saved to: $BACKUP"
    fi
}

phase_launch() {
    echo "[+] Phase 10: Launching Swarm..."
    cd "$WORKDIR"

    # Kill everything cleanly
    pkill -9 afl-fuzz 2>/dev/null; sleep 1
    screen -wipe 2>/dev/null || true

    # Build dictionary flag (use both manual + auto if available)
    DICT="-x dictionaries/skia.dict"
    [ -f dictionaries/auto_skia.dict ] && DICT="$DICT -x dictionaries/auto_skia.dict"

    # Common env — written to a temp file so screen inherits it cleanly
    cat > /tmp/afl_env.sh << ENVEOF
export AFL_AUTORESUME=1
export AFL_IMPORT_FIRST=1
export AFL_CMPLOG_ONLY_NEW=1
export AFL_MAP_SIZE=2560000
export AFL_NO_TRIM=1
export AFL_FAST_CAL=1
export AFL_SKIP_CPUFREQ=1
ENVEOF

    launch() {
        local NAME=$1 EXTRA_ENV=$2 BIN=$3 FLAGS=$4
        echo "    $NAME: $FLAGS"
        screen -dmS "$NAME" bash -c "
            source /tmp/afl_env.sh
            $EXTRA_ENV
            cd $WORKDIR
            exec afl-fuzz -i in -o out $FLAGS $DICT -m none -- ./$BIN
        "
    }

    AENV="export ASAN_OPTIONS='detect_leaks=0:symbolize=0:abort_on_error=1:detect_odr_violation=0'"
    UENV="export UBSAN_OPTIONS='halt_on_error=0:print_stacktrace=0:silence_unsigned_overflow=1'"

    launch "master"   "$AENV" "harness_skia_asan"  "-M master -l 2 -c ./harness_skia_cmplog -t 5000+"
    launch "ubsan"    "$UENV" "harness_skia_ubsan"  "-S ubsan -p explore -t 5000+"
    launch "asan_exp" "$AENV" "harness_skia_asan"   "-S asan_exp -p explore -t 5000+"
    launch "fast_4"   ""      "harness_skia_fast"   "-S fast_4 -p fast -t 2000"
    launch "fast_5"   ""      "harness_skia_fast"   "-S fast_5 -p rare -t 2000"
    launch "fast_6"   ""      "harness_skia_fast"   "-S fast_6 -p seek -t 2000"
    launch "fast_7"   ""      "harness_skia_fast"   "-S fast_7 -p coe -t 2000"
    launch "fast_8"   ""      "harness_skia_fast"   "-S fast_8 -p exploit -t 2000"

    sleep 2
    ALIVE=$(screen -ls 2>/dev/null | grep -c "Detached")
    echo "    $ALIVE/8 nodes alive"
    screen -ls 2>/dev/null | grep -E "\." || true
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
    screen -dmS triage bash -c "
        source /tmp/afl_env.sh
        export ASAN_OPTIONS='detect_leaks=0:symbolize=0:abort_on_error=1'
        cd $WORKDIR
        exec afl-fuzz -i triage_corpus -o triage_out -C -m none -t 5000+ -- ./harness_skia_asan
    "
}

# =====================================================================
# MAIN
# =====================================================================
phase_system_tune

case "$MODE" in
    "--resume")  phase_workspace; phase_backup_crashes; phase_launch ;;
    "--triage")  phase_workspace; phase_triage ;;
    "--diagnose") phase_workspace; phase_diagnose ;;
    *)
        phase_workspace; phase_harness; phase_dictionary
        phase_fetch; phase_corpus; phase_compile; phase_minimize
        phase_diagnose; phase_backup_crashes; phase_launch
        ;;
esac

echo ""
echo "================================================================"
echo "[DONE] SKIA FUZZER v8.0"
echo "================================================================"
echo ""
echo "Monitor:  cd ~/skia_fuzzing && watch -n 2 afl-whatsup -s -d out"
echo "Attach:   screen -r master"
echo "Triage:   ./launch_swarm.sh --triage"
echo "Diagnose: ./launch_swarm.sh --diagnose"
