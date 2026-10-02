/*
 * LTESniffer multi-cell refactor — Step 3b (case 3b: different EARFCN).
 *
 * DdcChannel is an ISampleSource that reads wideband samples from a
 * RingBuffer (produced at `fs_in` by WidebandCapture) and delivers them
 * to a CellPipeline at a lower sample rate (`fs_out`).
 *
 * The processing chain per pull() is:
 *   1. Read enough input samples from the ring.
 *   2. NCO: multiply by exp(-j*2*pi*delta_hz*n / fs_in) to shift the
 *      target cell from f_c + delta_hz down to baseband. The NCO phase
 *      is CONTINUOUS across calls (no reset per pull) so the output
 *      stream has no phase discontinuity at block boundaries.
 *   3. LPF: anti-aliasing low-pass FIR (on the SHIFTED signal) with
 *      passband occupied_bw/2 and stopband fs_out - occupied_bw/2. This both prevents aliasing before
 *      decimation and rejects the OTHER cell (which sits at a different
 *      frequency offset after the NCO).
 *   4. Resample: integer-ratio decimation (DecimChannel-style) or
 *      rational resampling (srsran_resample_arb) to fs_out.
 *
 * Special cases (handled by short-circuits, not separate classes):
 *   - delta_hz == 0  -> NCO is a no-op (multiplication by 1).
 *   - fs_in == fs_out -> LPF + resample are no-ops (passthrough).
 *
 * This single class therefore covers:
 *   - Same EARFCN, same BW (delta=0, ratio=1)  -> pure passthrough.
 *   - Same EARFCN, different BW (delta=0, ratio>1) -> DecimChannel.
 *   - Different EARFCN, same BW (delta!=0, ratio=1) -> NCO + LPF.
 *   - Different EARFCN, different BW (delta!=0, ratio>1) -> NCO + LPF + decimate.
 *
 * Thread model: one reader (the CellPipeline thread) calls pull().
 */
#pragma once

#include <cstdint>
#include <vector>

#include "ISampleSource.h"

class RingBuffer;

class DdcChannel : public ISampleSource {
public:
  /*
   * Build a DDC channel.
   *   ring           : source ring carrying samples at fs_in.
   *   delta_hz       : frequency offset of this cell from f_c (Hz).
   *                    0 for same-EARFCN cells.
   *   fs_in          : input sample rate (Hz) — the capture rate.
   *   fs_out         : output sample rate (Hz) — the cell's native rate.
   *   occupied_bw_hz : signal bandwidth of this cell (Hz). Used to
   *                    design the anti-aliasing LPF cutoff.
   *
   * Pre-conditions:
   *   - fs_in > 0, fs_out > 0, fs_out <= fs_in.
   *   - occupied_bw_hz > 0 and <= fs_in.
   *   - ratio = fs_in / fs_out is either an integer (use DecimChannel
   *     internally) or a rational number (use srsran_resample_arb).
   */
  DdcChannel(RingBuffer* ring,
             double delta_hz,
             double fs_in,
             double fs_out,
             double occupied_bw_hz);

  ~DdcChannel() override;

  // ISampleSource
  int  pull(cf_t* out[SRSRAN_MAX_PORTS],
            uint32_t nsamples,
            srsran_timestamp_t* t) override;
  void stop() override;

  // Non-interface helpers.
  bool isStopped() const;
  double deltaHz() const { return delta_hz_; }
  double fsIn()    const { return fs_in_; }
  double fsOut()   const { return fs_out_; }
  double ratio()   const { return fs_in_ / fs_out_; }

private:
  void designFilter();
  void designNco();
  void applyNco(std::vector<std::vector<cf_t>>& bufs, uint32_t offset, uint32_t n);

  RingBuffer* ring_;
  double      delta_hz_;
  double      fs_in_;
  double      fs_out_;
  double      occupied_bw_hz_;
  uint32_t    ratio_n_;   // numerator   (fs_out / gcd)
  uint32_t    ratio_d_;   // denominator (fs_in  / gcd)
  bool        ratio_is_integer_;

  // Anti-aliasing FIR coefficients (real-valued, symmetric).
  std::vector<float> taps_;
  uint32_t           filter_len_;

  // Per-port filter state: last (filter_len_ - 1) input samples.
  std::vector<std::vector<cf_t>> state_;

  // Per-port scratch buffer for newly-read samples (size = ratio_d * n + headroom).
  std::vector<std::vector<cf_t>> new_buf_;
  uint32_t new_buf_cap_ = 0;

  // NCO lookup table: one full period of exp(-j*2*pi*delta*n/fs_in).
  // nco_idx_ is the table position of the next input sample, so the
  // phase is continuous across pull() boundaries. Empty => delta == 0.
  std::vector<cf_t> nco_table_;
  uint32_t          nco_idx_ = 0;

  // Rational resampler state (only used when ratio is non-integer).
  // We use srsran_resample_arb per port. Heap-allocated because the
  // struct holds internal state (filter register) that would dangle
  // if a std::vector ever moved the struct during reallocation.
  // The type is fully defined in the .cc file (via srsran/phy/resampling/resample_arb.h).
  // We use void* here to avoid leaking the C type into the header.
  std::vector<void*> resamplers_;
  bool              resamplers_ok_ = false;

  // Per-port input buffer for the rational resampler (reused across reads).
  std::vector<std::vector<cf_t>>  in_buf_;
  uint32_t                        in_buf_cap_ = 0;

  // Per-port output accumulator (leftover from previous call is kept
  // at the front of the buffer).
  std::vector<std::vector<cf_t>>  out_buf_;
  uint32_t                        out_buf_count_ = 0;
  uint32_t                        out_buf_cap_ = 0;
};
