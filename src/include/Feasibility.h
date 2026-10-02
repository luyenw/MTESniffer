/*
 * LTESniffer multi-cell refactor — Step 3b (case 3b: different EARFCN).
 *
 * Feasibility is the pre-flight validation module. It runs BEFORE any RF
 * is opened or any pipeline is built. Its job is to:
 *   1. Validate the input cell list (EARFCN, PCI, PRB).
 *   2. Compute the capture plan (f_c, Fs_capture, Δk, ratio_k, LPF cutoff).
 *   3. Run checks A–H (see spec section 3A.2).
 *   4. Return a verdict: GO | GO_WITH_WARN | NO_GO.
 *
 * The orchestrator MUST refuse to proceed on NO_GO. On GO_WITH_WARN it
 * proceeds only if --force was passed.
 *
 * The plan returned by Feasibility is the SINGLE SOURCE OF TRUTH for the
 * orchestrator — it must not recompute f_c / Fs_capture / Δk independently.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace feas {

// ---- Input ----

struct CellInput {
  uint32_t    dl_earfcn;  // LTE downlink EARFCN
  uint32_t    pci;        // Physical Cell ID (0..503)
  uint32_t    nof_prb;    // 6, 15, 25, 50, 75, 100
};

// Hardware capability hint. If unknown, leave at zero and the module
// will fall back to a static table (with a WARN).
struct HwCaps {
  double max_sustained_rate_hz = 0.0;  // 0 = unknown
  double analog_rf_bw_hz       = 0.0;  // 0 = unknown
  std::string sdr_model;               // e.g. "B210", "X310", "" if unknown
};

struct Options {
  bool   force              = false;  // --force: allow GO_WITH_WARN
  double guard_hz           = 200e3;  // --guard-hz: transition-band guard
  bool   rational_resampler_supported = true;  // Step 5 capability
  uint32_t nof_rx_ant       = 1;
  bool   agc_enabled        = false;  // true if AGC is on (multi-cell wants fixed)
  bool   fixed_gain_set     = false;  // true if user passed -g
};

// ---- Derived per-cell info ----

struct CellPlan {
  CellInput  in;
  double     f_k_hz;          // center frequency of this cell
  double     bw_k_hz;         // occupied bandwidth (signal BW, not channel BW)
  double     occupied_bw_hz;  // ≈ bw_k_hz (signal BW)
  std::string band;           // LTE band name (e.g. "3", "7", "40")
  double     delta_hz;        // Δk = f_k − f_c
  double     fs_k_hz;         // native sample rate of this cell
  double     ratio_k;         // Fs_capture / fs_k (may be non-integer)
  bool       ratio_integer;   // true if ratio_k is an integer
};

// ---- Capture plan (single source of truth) ----

struct CapturePlan {
  double f_c_hz        = 0.0;   // RF center frequency
  double fs_capture_hz = 0.0;   // capture sample rate
  double span_hz       = 0.0;   // f_hi_edge − f_lo_edge
  double guard_hz      = 0.0;   // transition-band guard
  uint32_t max_prb     = 0;     // PRB count corresponding to fs_capture
  std::vector<CellPlan> cells;
};

// ---- Check results ----

enum class Level { PASS, WARN, FAIL };

struct CheckResult {
  std::string name;   // e.g. "A.field", "C.span"
  Level       level;
  std::string reason; // empty for PASS
};

enum class Verdict { GO, GO_WITH_WARN, NO_GO };

struct Report {
  Verdict                   verdict = Verdict::NO_GO;
  CapturePlan               plan;
  std::vector<CheckResult>  checks;   // one per check A..H
  std::string               summary;  // human-readable one-liner
};

// ---- Public API ----

/*
 * Run the full feasibility check.
 *   cells  : input cell list (must be non-empty).
 *   hw     : hardware capability hint (may be partially unknown).
 *   opts   : user options (force, guard, AGC, ...).
 * Returns a Report with verdict + plan + per-check results.
 *
 * The function NEVER opens the RF device. It only does math + static
 * table lookups. The orchestrator is responsible for probing the device
 * (if it wants) and feeding the result back via hw.max_sustained_rate_hz.
 */
Report validate(const std::vector<CellInput>& cells,
                const HwCaps& hw,
                const Options& opts);

/*
 * Pretty-print a Report to stdout. Used by the orchestrator before
 * opening the RF.
 */
void printReport(const Report& r);

/*
 * Map an EARFCN to (band, f_dl_hz). Returns false if the EARFCN is not
 * in any known band. Exposed for unit testing.
 */
bool earfcnToFreq(uint32_t dl_earfcn, std::string& band_out, double& f_dl_hz_out);

/*
 * Compute the LTE signal bandwidth (Hz) for a given PRB count. Returns
 * -1.0 if the PRB count is invalid.
 */
double prbToBandwidthHz(uint32_t nof_prb);

/*
 * Compute the LTE native sample rate (Hz) for a given PRB count.
 * Returns -1.0 if invalid.
 */
double prbToSampleRateHz(uint32_t nof_prb);

}  // namespace feas
