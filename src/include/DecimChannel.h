/*
 * LTESniffer multi-cell refactor — Step 4.
 *
 * DecimChannel is an ISampleSource that reads wideband samples from a
 * RingBuffer (produced at `fs_capture` by WidebandCapture) and delivers
 * them to a CellPipeline at a lower, integer-ratio sample rate
 * (`fs_capture / ratio`).
 *
 * The down-sampling is preceded by an anti-aliasing low-pass FIR filter
 * (windowed-sinc, Hamming window, cutoff = 1/ratio normalised to the
 * INPUT rate — i.e. the first sinc zero sits at the OUTPUT Nyquist).
 * The filter state (last `filter_len - 1` input samples per port) is
 * carried across calls so successive pull() invocations produce a
 * continuous filtered stream.
 *
 * Invariants:
 *   - ratio >= 1 and is an INTEGER (Step 4).
 *   - ratio == 1 is supported (acts as a passthrough with no filtering)
 *     so callers can always use DecimChannel regardless of the ratio.
 *   - The ratio must equal `max_prb / cell.nof_prb` exactly.
 *
 * For non-integer ratios (e.g. 100/15, 50/6) a rational resampler is
 * needed — that is Step 5.
 *
 * Thread model: one reader (the CellPipeline thread) calls pull(). The
 * underlying RingBuffer handles SPSC synchronisation with the writer.
 */
#pragma once

#include <cstdint>
#include <vector>

#include "ISampleSource.h"

class RingBuffer;

class DecimChannel : public ISampleSource {
public:
  /*
   * Build a decimator.
   *   ring  : source ring carrying samples at fs_capture.
   *   ratio : integer decimation factor (>= 1).
   */
  DecimChannel(RingBuffer* ring, uint32_t ratio);

  // ISampleSource
  int  pull(cf_t* out[SRSRAN_MAX_PORTS],
            uint32_t nsamples,
            srsran_timestamp_t* t) override;
  void stop() override;

  // Non-interface helper: true once the underlying ring has been stopped.
  bool isStopped() const;

  uint32_t ratio() const { return ratio_; }

private:
  void designFilter();

  RingBuffer* ring_;
  uint32_t    ratio_;
  uint32_t    filter_len_;

  // Anti-aliasing FIR coefficients (real-valued, symmetric).
  std::vector<float> taps_;

  // Per-port filter state: last (filter_len_ - 1) input samples.
  std::vector<std::vector<cf_t>> state_;

  // Per-port scratch buffer for newly-read samples (size = ratio * n).
  std::vector<std::vector<cf_t>> new_buf_;
  uint32_t new_buf_cap_ = 0;
};
