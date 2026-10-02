/*
 * LTESniffer multi-cell refactor — Step 3b (case 3b: different EARFCN).
 *
 * Feasibility implementation. See Feasibility.h for the contract.
 *
 * EARFCN table covers the bands most commonly used in lab / scanner
 * scenarios. Bands not listed return false from earfcnToFreq().
 */
#include "include/Feasibility.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace feas {

// ---- EARFCN table (3GPP TS 36.101, Table 5.7.3-1) ----
// Each entry: { band_name, f_dl_low_Hz, n_offs, range_min, range_max }.
// f_dl = f_dl_low + 0.1 * (EARFCN - n_offs)  [Hz]
struct EarfcnEntry {
  const char* band;
  double      f_dl_low;  // Hz
  uint32_t    n_offs;
  uint32_t    range_min;
  uint32_t    range_max;
};

static const EarfcnEntry kEarfcnTable[] = {
  // FDD bands (most common)
  {"1",  2110e6,    0,    0,    599},
  {"2",  1930e6,  600,  600,   1199},
  {"3",  1805e6, 1200, 1200,   1949},
  {"4",  2110e6, 1950, 1950,   2399},
  {"5",  869e6,  2400, 2400,   2649},
  {"7",  2620e6, 2750, 2750,   3449},
  {"8",  925e6,  3450, 3450,   3799},
  {"12", 729e6,  5010, 5010,   5179},
  {"13", 746e6,  5180, 5180,   5279},
  {"17", 734e6,  5730, 5730,   5849},
  {"20", 791e6,  6150, 6150,   6449},
  {"25", 1930e6, 8040, 8040,   8689},
  {"26", 859e6,  8690, 8690,   9039},
  {"28", 758e6,  9210, 9210,   9659},
  // TDD bands
  {"38", 2570e6, 37750, 37750, 38249},
  {"39", 1880e6, 38250, 38250, 38649},
  {"40", 2300e6, 38650, 38650, 39649},
  {"41", 2496e6, 39650, 39650, 41589},
};

bool earfcnToFreq(uint32_t dl_earfcn, std::string& band_out, double& f_dl_hz_out) {
  for (const auto& e : kEarfcnTable) {
    if (dl_earfcn >= e.range_min && dl_earfcn <= e.range_max) {
      band_out    = e.band;
      // 3GPP TS 36.101: f_DL [MHz] = f_DL_low [MHz] + 0.1 * (EARFCN - N_offs).
      // f_dl_low is stored in Hz, so multiply the step by 1e6 to stay in Hz.
      f_dl_hz_out = e.f_dl_low + 1e5 * static_cast<double>(static_cast<int>(dl_earfcn) - static_cast<int>(e.n_offs));
      return true;
    }
  }
  return false;
}

// ---- PRB → bandwidth / sample rate ----
// Signal BW = nof_prb * 12 * 15e3 = nof_prb * 180e3 Hz.
// Native sample rate = srsran_sampling_freq_hz(nof_prb) = 15000 * symbol_sz.
// We use the standard (power-of-2) rates here, matching srsRAN's
// srsran_symbol_sz_power2().

double prbToBandwidthHz(uint32_t nof_prb) {
  if (nof_prb == 0) return -1.0;
  return static_cast<double>(nof_prb) * 12.0 * 15e3;
}

double prbToSampleRateHz(uint32_t nof_prb) {
  // srsRAN's standard rates (matches srsran_sampling_freq_hz):
  //   6  -> 1.92 MHz, 15 -> 3.84 MHz, 25 -> 5.76 MHz,
  //   50 -> 11.52 MHz, 75 -> 15.36 MHz, 100 -> 23.04 MHz.
  // NOTE: These are NOT power-of-2 rates. srsRAN uses non-power-of-2
  // FFT internally and expects these exact rates. Using power-of-2
  // rates (e.g. 7.68 MHz for PRB 25) breaks PSS correlation.
  switch (nof_prb) {
    case 6:   return 1.92e6;
    case 15:  return 3.84e6;
    case 25:  return 5.76e6;
    case 50:  return 11.52e6;
    case 75:  return 15.36e6;
    case 100: return 23.04e6;
    default:  return -1.0;
  }
}

// ---- Static SDR capability table (fallback when hw.* is unknown) ----
// Numbers are conservative; the spec says "GẦN ĐÚNG — phải probe/verify".
struct SdrCaps {
  const char* model_pattern;  // substring match against rf_args
  double      analog_bw_hz;
  double      max_rate_hz;
};

static const SdrCaps kSdrTable[] = {
  {"B210",     56e6,   30.72e6},
  {"B200mini", 56e6,   30.72e6},
  {"B200",     56e6,   30.72e6},
  {"X310",    160e6,  100e6},
  {"N210",     56e6,   25e6},
  {"N200",     56e6,   25e6},
};

static void lookupStaticCaps(const std::string& rf_args,
                             double& analog_bw_out,
                             double& max_rate_out) {
  analog_bw_out = 0.0;
  max_rate_out  = 0.0;
  for (const auto& s : kSdrTable) {
    if (rf_args.find(s.model_pattern) != std::string::npos) {
      analog_bw_out = s.analog_bw_hz;
      max_rate_out  = s.max_rate_hz;
      return;
    }
  }
}

// ---- Helpers ----

static void addCheck(std::vector<CheckResult>& v,
                     const std::string& name,
                     Level lvl,
                     const std::string& reason = "") {
  v.push_back(CheckResult{name, lvl, reason});
}

static bool isValidPrb(uint32_t p) {
  return p == 6 || p == 15 || p == 25 || p == 50 || p == 75 || p == 100;
}

// ---- Main entry ----

Report validate(const std::vector<CellInput>& cells_in,
                const HwCaps& hw,
                const Options& opts) {
  Report r;
  r.plan.guard_hz = opts.guard_hz;

  // ---- A. Field validity ----
  if (cells_in.empty()) {
    addCheck(r.checks, "A.input", Level::FAIL, "no cells provided");
    r.verdict  = Verdict::NO_GO;
    r.summary  = "no cells";
    return r;
  }
  for (size_t i = 0; i < cells_in.size(); i++) {
    const auto& c = cells_in[i];
    if (!isValidPrb(c.nof_prb)) {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "cell[%zu] PRB=%u not in {6,15,25,50,75,100}", i, c.nof_prb);
      addCheck(r.checks, "A.field", Level::FAIL, buf);
    }
    if (c.pci > 503) {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "cell[%zu] PCI=%u out of range 0..503", i, c.pci);
      addCheck(r.checks, "A.field", Level::FAIL, buf);
    }
    std::string band;
    double f_dl = 0.0;
    if (!earfcnToFreq(c.dl_earfcn, band, f_dl)) {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "cell[%zu] DL_EARFCN=%u not in any known band", i, c.dl_earfcn);
      addCheck(r.checks, "A.field", Level::FAIL, buf);
    }
  }
  // Duplicate (dl_earfcn, pci) check
  for (size_t i = 0; i < cells_in.size(); i++) {
    for (size_t j = i + 1; j < cells_in.size(); j++) {
      if (cells_in[i].dl_earfcn == cells_in[j].dl_earfcn &&
          cells_in[i].pci       == cells_in[j].pci) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "cells[%zu] and cells[%zu] duplicate (DL_EARFCN=%u,PCI=%u)",
                      i, j, cells_in[i].dl_earfcn, cells_in[i].pci);
        addCheck(r.checks, "A.field", Level::FAIL, buf);
      }
    }
  }
  // If any A.field FAIL, bail out early.
  for (const auto& c : r.checks) {
    if (c.level == Level::FAIL) {
      r.verdict = Verdict::NO_GO;
      r.summary = "invalid input fields";
      return r;
    }
  }
  addCheck(r.checks, "A.field", Level::PASS);

  // ---- B. Per-cell frequency derivation ----
  r.plan.cells.clear();
  r.plan.cells.reserve(cells_in.size());
  std::string first_band;
  bool multi_band = false;
  for (const auto& ci : cells_in) {
    CellPlan cp;
    cp.in = ci;
    if (!earfcnToFreq(ci.dl_earfcn, cp.band, cp.f_k_hz)) {
      // Already caught in A; skip.
      continue;
    }
    cp.bw_k_hz        = prbToBandwidthHz(ci.nof_prb);
    cp.occupied_bw_hz = cp.bw_k_hz;
    cp.fs_k_hz        = prbToSampleRateHz(ci.nof_prb);
    if (first_band.empty()) first_band = cp.band;
    else if (cp.band != first_band) multi_band = true;
    r.plan.cells.push_back(cp);
  }
  if (multi_band) {
    addCheck(r.checks, "B.band",
             Level::WARN,
             "cells span multiple LTE bands; one LO may not be optimal for all");
  } else {
    addCheck(r.checks, "B.band", Level::PASS);
  }

  // ---- C. Span vs analog RF BW ----
  double f_lo_edge =  1e18;
  double f_hi_edge = -1e18;
  for (const auto& cp : r.plan.cells) {
    f_lo_edge = std::min(f_lo_edge, cp.f_k_hz - cp.bw_k_hz / 2.0);
    f_hi_edge = std::max(f_hi_edge, cp.f_k_hz + cp.bw_k_hz / 2.0);
  }
  r.plan.span_hz = f_hi_edge - f_lo_edge;
  r.plan.f_c_hz  = (f_lo_edge + f_hi_edge) / 2.0;

  // Determine analog RF BW: prefer hw, fall back to static table.
  double analog_bw = hw.analog_rf_bw_hz;
  if (analog_bw <= 0.0) {
    lookupStaticCaps(hw.sdr_model, analog_bw, /*unused*/ analog_bw);
    // (lookupStaticCaps sets both analog_bw and max_rate; we re-call below.)
  }
  if (analog_bw > 0.0) {
    if (r.plan.span_hz + 2.0 * opts.guard_hz > analog_bw) {
      char buf[160];
      std::snprintf(buf, sizeof(buf),
                    "span %.3f MHz + 2*guard %.3f MHz > analog RF BW %.3f MHz",
                    r.plan.span_hz / 1e6, 2.0 * opts.guard_hz / 1e6, analog_bw / 1e6);
      addCheck(r.checks, "C.span", Level::FAIL, buf);
    } else {
      addCheck(r.checks, "C.span", Level::PASS);
    }
  } else {
    addCheck(r.checks, "C.span", Level::WARN,
             "analog RF BW unknown (no probe, no static match); cannot validate span");
  }

  // ---- D. Sustained sample rate ----
  // Choose Fs_capture as the smallest standard rate that covers span + 2*guard.
  // Standard candidates (Hz): 1.92, 3.84, 5.76, 11.52, 15.36, 23.04, 30.72e6.
  // These match srsran_sampling_freq_hz() for PRB 6, 15, 25, 50, 75, 100.
  static const double kFsCandidates[] = {
    1.92e6, 3.84e6, 5.76e6, 11.52e6, 15.36e6, 23.04e6, 30.72e6
  };
  double need = r.plan.span_hz + 2.0 * opts.guard_hz;
  // Prefer the smallest candidate that is an INTEGER multiple of every
  // cell's native rate (clean polyphase decimation, e.g. 23.04 = 4 x 5.76
  // for PRB 25), and only fall back to a rational ratio if none fits.
  const double max_rate_hint = [&] {
    double mr = hw.max_sustained_rate_hz, dummy;
    if (mr <= 0.0) lookupStaticCaps(hw.sdr_model, dummy, mr);
    return mr;
  }();
  double fs_capture = 0.0;
  for (double f : kFsCandidates) {
    if (f < need) continue;
    if (max_rate_hint > 0.0 && f > max_rate_hint) break;
    bool all_int = true;
    for (const auto& cp : r.plan.cells) {
      const double q = f / cp.fs_k_hz;
      if (std::fabs(q - std::round(q)) > 1e-6) { all_int = false; break; }
    }
    if (all_int) { fs_capture = f; break; }
  }
  if (fs_capture == 0.0) {
    for (double f : kFsCandidates) {
      if (f >= need) { fs_capture = f; break; }
    }
  }
  if (fs_capture == 0.0) {
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "no standard Fs_candidate covers span %.3f MHz + 2*guard",
                  need / 1e6);
    addCheck(r.checks, "D.rate", Level::FAIL, buf);
  } else {
    r.plan.fs_capture_hz = fs_capture;
    // Map back to a PRB count (for buffer sizing).
    // Matches srsran_sampling_freq_hz() reverse mapping.
    if      (std::fabs(fs_capture - 1.92e6)  < 1.0) r.plan.max_prb = 6;
    else if (std::fabs(fs_capture - 3.84e6)  < 1.0) r.plan.max_prb = 15;
    else if (std::fabs(fs_capture - 5.76e6)  < 1.0) r.plan.max_prb = 25;
    else if (std::fabs(fs_capture - 11.52e6) < 1.0) r.plan.max_prb = 50;
    else if (std::fabs(fs_capture - 15.36e6) < 1.0) r.plan.max_prb = 75;
    else if (std::fabs(fs_capture - 23.04e6) < 1.0) r.plan.max_prb = 100;
    else if (std::fabs(fs_capture - 30.72e6) < 1.0) r.plan.max_prb = 100;  // buffer sizing only
    else r.plan.max_prb = 0;

    double max_rate = hw.max_sustained_rate_hz;
    if (max_rate <= 0.0) {
      double dummy;
      lookupStaticCaps(hw.sdr_model, dummy, max_rate);
    }
    if (max_rate > 0.0) {
      if (fs_capture > max_rate) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "Fs_capture %.3f MHz > SDR sustained max %.3f MHz",
                      fs_capture / 1e6, max_rate / 1e6);
        addCheck(r.checks, "D.rate", Level::FAIL, buf);
      } else if (fs_capture > 0.8 * max_rate) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "Fs_capture %.3f MHz close to SDR max %.3f MHz (overrun risk)",
                      fs_capture / 1e6, max_rate / 1e6);
        addCheck(r.checks, "D.rate", Level::WARN, buf);
      } else {
        addCheck(r.checks, "D.rate", Level::PASS);
      }
    } else {
      addCheck(r.checks, "D.rate", Level::WARN,
               "SDR sustained rate unknown; cannot validate Fs_capture");
    }
  }

  // ---- E. Resample ratio per cell ----
  bool any_noninteger = false;
  for (auto& cp : r.plan.cells) {
    cp.ratio_k = r.plan.fs_capture_hz / cp.fs_k_hz;
    cp.ratio_integer = (std::fabs(cp.ratio_k - std::round(cp.ratio_k)) < 1e-3);
    if (!cp.ratio_integer) any_noninteger = true;
    cp.delta_hz = cp.f_k_hz - r.plan.f_c_hz;
  }
  if (any_noninteger && !opts.rational_resampler_supported) {
    addCheck(r.checks, "E.ratio", Level::FAIL,
             "non-integer resample ratio required but rational resampler not supported");
  } else if (any_noninteger) {
    addCheck(r.checks, "E.ratio", Level::WARN,
             "non-integer resample ratio; using rational resampler (Step 5)");
  } else {
    addCheck(r.checks, "E.ratio", Level::PASS);
  }

  // ---- F. LO leakage / DC ----
  // If f_c is within ±(occupied_bw/2) of any cell center, the LO/DC
  // offset falls inside that cell's signal — WARN.
  bool lo_in_cell = false;
  for (const auto& cp : r.plan.cells) {
    if (std::fabs(r.plan.f_c_hz - cp.f_k_hz) < cp.occupied_bw_hz / 2.0) {
      lo_in_cell = true;
      break;
    }
  }
  if (lo_in_cell) {
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "f_c=%.3f MHz falls inside a cell's signal BW; consider shifting to a guard band",
                  r.plan.f_c_hz / 1e6);
    addCheck(r.checks, "F.lo_dc", Level::WARN, buf);
  } else {
    addCheck(r.checks, "F.lo_dc", Level::PASS);
  }

  // ---- G. Gain ----
  if (cells_in.size() > 1) {
    if (opts.agc_enabled) {
      addCheck(r.checks, "G.gain", Level::WARN,
               "AGC enabled with N>1 cells; strong cell may desense weak cell — use fixed gain");
    } else if (!opts.fixed_gain_set) {
      addCheck(r.checks, "G.gain", Level::FAIL,
               "N>1 cells require fixed gain (-g); AGC is not safe with shared front-end");
    } else {
      addCheck(r.checks, "G.gain", Level::PASS);
    }
  } else {
    addCheck(r.checks, "G.gain", Level::PASS, "single cell");
  }

  // ---- H. Decode load (rough) ----
  uint32_t sum_prb = 0;
  for (const auto& cp : r.plan.cells) sum_prb += cp.in.nof_prb;
  if (cells_in.size() >= 4 || sum_prb >= 200) {
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "N=%zu cells, ΣPRB=%u — may not run real-time on a modest host",
                  cells_in.size(), sum_prb);
    addCheck(r.checks, "H.load", Level::WARN, buf);
  } else {
    addCheck(r.checks, "H.load", Level::PASS);
  }

  // ---- Verdict ----
  bool any_fail = false, any_warn = false;
  for (const auto& c : r.checks) {
    if (c.level == Level::FAIL) any_fail = true;
    if (c.level == Level::WARN) any_warn = true;
  }
  if (any_fail) {
    r.verdict = Verdict::NO_GO;
    r.summary = "one or more checks FAILED";
  } else if (any_warn) {
    r.verdict = Verdict::GO_WITH_WARN;
    r.summary = "all checks passed with warnings (use --force to proceed)";
  } else {
    r.verdict = Verdict::GO;
    r.summary = "all checks passed";
  }
  return r;
}

void printReport(const Report& r) {
  std::printf("\n=== Feasibility report ===\n");
  std::printf("Cells (%zu):\n", r.plan.cells.size());
  for (const auto& cp : r.plan.cells) {
    std::printf("  DL_EARFCN=%u PCI=%u PRB=%u  band=%s  f_k=%.3f MHz  "
                "BW=%.3f MHz  fs_k=%.3f MHz  Δ=%.3f MHz  ratio=%.3f (%s)\n",
                cp.in.dl_earfcn, cp.in.pci, cp.in.nof_prb, cp.band.c_str(),
                cp.f_k_hz / 1e6, cp.bw_k_hz / 1e6, cp.fs_k_hz / 1e6,
                cp.delta_hz / 1e6, cp.ratio_k,
                cp.ratio_integer ? "int" : "rational");
  }
  std::printf("f_c = %.3f MHz    Fs_capture = %.3f MHz    span = %.3f MHz    guard = %.3f MHz\n",
              r.plan.f_c_hz / 1e6, r.plan.fs_capture_hz / 1e6,
              r.plan.span_hz / 1e6, r.plan.guard_hz / 1e6);
  std::printf("Checks:\n");
  for (const auto& c : r.checks) {
    const char* tag = "?";
    switch (c.level) {
      case Level::PASS: tag = "PASS"; break;
      case Level::WARN: tag = "WARN"; break;
      case Level::FAIL: tag = "FAIL"; break;
    }
    std::printf("  %-10s %s%s%s\n",
                c.name.c_str(), tag,
                c.reason.empty() ? "" : "  ",
                c.reason.c_str());
  }
  const char* v = "?";
  switch (r.verdict) {
    case Verdict::GO:           v = "GO"; break;
    case Verdict::GO_WITH_WARN: v = "GO_WITH_WARN (need --force)"; break;
    case Verdict::NO_GO:        v = "NO_GO"; break;
  }
  std::printf("Verdict: %s\n", v);
  std::printf("Summary: %s\n", r.summary.c_str());
  std::printf("==========================\n\n");
}

}  // namespace feas
