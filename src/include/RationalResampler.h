/*
 * LTESniffer multi-cell refactor — Step 5.
 *
 * RationalResampler is an ISampleSource that reads wideband samples from
 * a RingBuffer (produced at `fs_capture` by WidebandCapture) and delivers
 * them to a CellPipeline at an ARBITRARY rational sample rate
 * (`fs_capture * cell_prb / max_prb`).
 *
 * It uses srsran_resample_arb (polyphase filter bank) per antenna port.
 * The resampler's rate is `fs_cell / fs_capture = cell_prb / max_prb`.
 *
 * Unlike DecimChannel (integer ratio), srsran_resample_arb_compute does
 * not guarantee an exact output count for an arbitrary input count. To
 * produce exactly `nsamples` output samples per pull() we:
 *   - Feed `ratio_d * k` input samples in one go, which yields
 *     `ratio_n * k` (+/- filter delay) output samples.
 *   - Accumulate output in an internal buffer until we have at least
 *     `nsamples`, then copy and shift.
 *
 * Invariants:
 *   - max_prb > cell_prb (the cell is strictly narrower than the capture).
 *   - max_prb % cell_prb != 0 (non-integer ratio; use DecimChannel
 *     for integer ratios, PassthroughChannel for ratio==1).
 *
 * Thread model: one reader (the CellPipeline thread) calls pull().
 */
#pragma once

#include <cstdint>
#include <memory>
#include <vector>

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/resampling/resample_arb.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#include "ISampleSource.h"

class RingBuffer;

class RationalResampler : public ISampleSource {
public:
  /*
   * Build a rational resampler.
   *   ring     : source ring carrying samples at fs_capture (max_prb rate).
   *   max_prb  : capture-side PRB count (denominator of the ratio).
   *   cell_prb : cell-side PRB count (numerator of the ratio).
   */
  RationalResampler(RingBuffer* ring, uint32_t max_prb, uint32_t cell_prb);

  ~RationalResampler() override;

  // ISampleSource
  int  pull(cf_t* out[SRSRAN_MAX_PORTS],
            uint32_t nsamples,
            srsran_timestamp_t* t) override;
  void stop() override;

  // Non-interface helper.
  bool isStopped() const;

  uint32_t ratioN() const { return ratio_n_; }
  uint32_t ratioD() const { return ratio_d_; }

private:
  RingBuffer* ring_;
  uint32_t    max_prb_;
  uint32_t    cell_prb_;
  uint32_t    ratio_n_;   // = cell_prb
  uint32_t    ratio_d_;   // = max_prb
  float       ratio_;     // = ratio_n_ / ratio_d_ as float

  // One srsran_resample_arb_t per antenna port. Heap-allocated because
  // the struct holds internal state (filter register) that would dangle
  // if a std::vector ever moved the struct during reallocation.
  // srsran_resample_arb_t is a POD type with no allocation, so a plain
  // unique_ptr<srsran_resample_arb_t[]> is sufficient.
  std::vector<std::unique_ptr<srsran_resample_arb_t>> resamplers_;
  bool                                               resamplers_ok_ = false;

  // Per-port input buffer (reused across reads).
  std::vector<std::vector<cf_t>>  in_buf_;
  uint32_t                        in_buf_cap_ = 0;

  // Per-port output accumulator (leftover from previous call is kept
  // at the front of the buffer).
  std::vector<std::vector<cf_t>>  out_buf_;
  uint32_t                        out_buf_count_ = 0;
  uint32_t                        out_buf_cap_ = 0;
};
