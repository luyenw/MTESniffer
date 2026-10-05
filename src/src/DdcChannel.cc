/*
 * LTESniffer multi-cell refactor — Step 3b (case 3b: different EARFCN).
 *
 * DdcChannel implementation. See DdcChannel.h for the design.
 */
#include "include/DdcChannel.h"
#include "include/RingBuffer.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstdio>

// C++11 polyfill for std::make_unique (C++14 feature).
#if __cplusplus < 201402L
namespace std {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
#endif

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif
#include "srsran/phy/resampling/resample_arb.h"
#include "srsran/phy/utils/vector.h"
#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ---- Helpers ----

// Greatest common divisor (Euclidean).
static uint32_t gcd_u32(uint32_t a, uint32_t b) {
  while (b != 0) {
    uint32_t t = b;
    b = a % b;
    a = t;
  }
  return a;
}

// ---- DdcChannel ----

DdcChannel::DdcChannel(RingBuffer* ring,
                       double delta_hz,
                       double fs_in,
                       double fs_out,
                       double occupied_bw_hz)
  : ring_(ring),
    delta_hz_(delta_hz),
    fs_in_(fs_in),
    fs_out_(fs_out),
    occupied_bw_hz_(occupied_bw_hz)
{
  // Compute ratio as a rational number n/d.
  // For standard LTE rates (1.92, 3.84, 5.76, 11.52, 15.36, 23.04,
  // 30.72 MHz) the ratio is often an exact integer.
  const uint32_t fs_in_hz  = static_cast<uint32_t>(std::lround(fs_in));
  const uint32_t fs_out_hz = static_cast<uint32_t>(std::lround(fs_out));
  const uint32_t g = gcd_u32(fs_in_hz, fs_out_hz);
  ratio_n_ = fs_out_hz / g;
  ratio_d_ = fs_in_hz  / g;
  ratio_is_integer_ = (ratio_n_ == 1);

  const uint32_t nports = ring_->numPorts();
  state_.resize(nports);
  new_buf_.resize(nports);
  in_buf_.resize(nports);
  out_buf_.resize(nports);

  designFilter();
  designNco();
  for (auto& s : state_) {
    s.assign(filter_len_ - 1, cf_t{0.0f, 0.0f});
  }

  // Initialise rational resamplers only if needed.
  if (!ratio_is_integer_) {
    resamplers_.resize(nports, nullptr);
    const float rate = static_cast<float>(fs_out_hz) / static_cast<float>(fs_in_hz);
    for (uint32_t p = 0; p < nports; p++) {
      auto* r = new srsran_resample_arb_t();
      srsran_resample_arb_init(r, rate, /*interpolate=*/true);
      resamplers_[p] = r;
    }
    resamplers_ok_ = true;
  }

  printf("[DdcChannel] delta=%.3f MHz fs_in=%.3f MHz fs_out=%.3f MHz "
         "ratio=%u/%u (%s) LPF taps=%u NCO table=%zu\n",
         delta_hz_ / 1e6, fs_in_ / 1e6, fs_out_ / 1e6, ratio_d_, ratio_n_,
         ratio_is_integer_ ? "int" : "rational", filter_len_, nco_table_.size());
}

DdcChannel::~DdcChannel() {
  for (auto* r : resamplers_) {
    delete static_cast<srsran_resample_arb_t*>(r);
  }
  resamplers_.clear();
}

void DdcChannel::designFilter() {
  // Windowed-sinc low-pass (Hamming, ~53 dB stopband), applied AFTER the
  // NCO, i.e. on the cell shifted to baseband.
  //   passband edge : occupied_bw/2            (keep the whole cell)
  //   stopband edge : fs_out - occupied_bw/2   (anything above this would
  //                   alias INTO the passband after resampling to fs_out)
  // Neighbouring cells sit well beyond the stopband edge and are rejected.
  const double f_pass = occupied_bw_hz_ / 2.0;
  double f_stop = fs_out_ - occupied_bw_hz_ / 2.0;
  if (f_stop <= f_pass) f_stop = f_pass + 0.1 * fs_out_;
  const double f_cut  = 0.5 * (f_pass + f_stop);           // Hz
  const double trans  = (f_stop - f_pass) / fs_in_;        // cycles/sample

  // Hamming: transition width ~= 3.3 / N.
  uint32_t len = static_cast<uint32_t>(std::ceil(3.3 / trans));
  len = std::max<uint32_t>(len, 4 * ratio_d_ + 1);
  len = std::min<uint32_t>(len, 511);
  if ((len % 2) == 0) len++;
  filter_len_ = len;

  const double wc     = 2.0 * f_cut / fs_in_;  // normalised, 1.0 == fs_in/2
  const int    center = static_cast<int>((filter_len_ - 1) / 2);

  taps_.assign(filter_len_, 0.0f);
  double sum = 0.0;
  std::vector<double> h(filter_len_);
  for (uint32_t i = 0; i < filter_len_; i++) {
    const double n = static_cast<double>(static_cast<int>(i) - center);
    const double sinc_val = (n == 0.0) ? 1.0 : std::sin(M_PI * wc * n) / (M_PI * wc * n);
    const double w = 0.54 - 0.46 * std::cos(2.0 * M_PI * i / (filter_len_ - 1));
    h[i] = sinc_val * w;
    sum += h[i];
  }
  // Normalise for unity DC gain.
  for (uint32_t i = 0; i < filter_len_; i++) {
    taps_[i] = static_cast<float>(h[i] / sum);
  }
}

void DdcChannel::designNco() {
  // exp(-j*2*pi*delta*n/fs_in) is periodic with period
  //   P = fs_in / gcd(fs_in, |delta|)   (both in integer Hz).
  // With LTE rates (multiples of 1.92 MHz) and delta a multiple of 50 kHz,
  // P <= a few thousand samples, so a lookup table is exact and cheap
  // (no per-sample sin/cos, no phase drift).
  nco_table_.clear();
  nco_idx_ = 0;
  const int64_t d_hz  = std::llabs(std::llround(delta_hz_));
  if (d_hz == 0) return;  // NCO disabled
  const uint32_t fs_hz = static_cast<uint32_t>(std::lround(fs_in_));
  const uint32_t g     = gcd_u32(fs_hz, static_cast<uint32_t>(d_hz));
  const uint32_t period = fs_hz / g;
  if (period > (1u << 20)) {
    fprintf(stderr, "[DdcChannel] NCO period %u too large; delta %.1f Hz not supported\n",
            period, delta_hz_);
    return;
  }
  nco_table_.resize(period);
  const double w = -2.0 * M_PI * delta_hz_ / fs_in_;
  for (uint32_t n = 0; n < period; n++) {
    const double phi = w * static_cast<double>(n);
    nco_table_[n] = cf_t{static_cast<float>(std::cos(phi)),
                         static_cast<float>(std::sin(phi))};
  }
}

// Multiply `n` samples (identically on every port) by the NCO, advancing
// the phase once for the whole block.
void DdcChannel::applyNco(std::vector<std::vector<cf_t>>& bufs, uint32_t offset, uint32_t n) {
  if (nco_table_.empty()) return;
  const uint32_t period = static_cast<uint32_t>(nco_table_.size());
  for (auto& b : bufs) {
    cf_t*    x   = b.data() + offset;
    uint32_t idx = nco_idx_;
    uint32_t done = 0;
    while (done < n) {
      const uint32_t chunk = std::min(n - done, period - idx);
      srsran_vec_prod_ccc(x + done, nco_table_.data() + idx, x + done, chunk);
      done += chunk;
      idx = (idx + chunk) % period;
    }
  }
  nco_idx_ = static_cast<uint32_t>((nco_idx_ + static_cast<uint64_t>(n)) % period);
}

int DdcChannel::pull(cf_t* out[SRSRAN_MAX_PORTS],
                     uint32_t nsamples,
                     srsran_timestamp_t* t) {
  if (nsamples == 0) return 0;
  if (isStopped()) return -1;

  const uint32_t nports    = static_cast<uint32_t>(state_.size());
  const uint32_t state_len = filter_len_ - 1;

  if (ratio_is_integer_) {
    // ---- Integer-ratio path: NCO -> LPF -> keep every ratio_d_-th ----
    // Working buffer layout per port: [ history (L-1) | new (d*n) ].
    // Exactly d*n new samples are consumed per call, so the stream stays
    // sample-accurate (no drops at pull boundaries).
    const uint32_t to_read = ratio_d_ * nsamples;
    const uint32_t total   = state_len + to_read;

    if (new_buf_cap_ < total) {
      const uint32_t new_cap = std::max(total, new_buf_cap_ * 2);
      for (auto& b : new_buf_) b.resize(new_cap);
      new_buf_cap_ = new_cap;
    }

    std::vector<cf_t*> new_buf_ptrs(nports);
    for (uint32_t p = 0; p < nports; p++) {
      new_buf_ptrs[p] = new_buf_[p].data() + state_len;
    }
    int ret = ring_->read(new_buf_ptrs.data(), to_read);
    if (ret < 0) return -1;
    if (static_cast<uint32_t>(ret) < to_read) return -1;

    // Shift the target cell to baseband BEFORE filtering.
    applyNco(new_buf_, state_len, to_read);

    for (uint32_t p = 0; p < nports; p++) {
      cf_t* buf = new_buf_[p].data();
      std::copy(state_[p].begin(), state_[p].end(), buf);
      // Output i uses input window ending at history+ (i+1)*d - 1.
      for (uint32_t i = 0; i < nsamples; i++) {
        out[p][i] = srsran_vec_dot_prod_cfc(buf + (i + 1) * ratio_d_ - 1,
                                            taps_.data(), filter_len_);
      }
      std::copy(buf + total - state_len, buf + total, state_[p].begin());
    }
  } else {
    // ---- Rational-ratio path: NCO -> LPF (full rate) -> resample_arb ----
    // srsran_resample_arb only has an 8-tap polyphase filter and does not
    // anti-alias for decimation, so the LPF must be applied first.
    const uint32_t needed_out = nsamples + 2 * ratio_n_;
    if (out_buf_cap_ < needed_out) {
      const uint32_t new_cap = std::max(needed_out, out_buf_cap_ * 2);
      for (auto& b : out_buf_) b.resize(new_cap);
      out_buf_cap_ = new_cap;
    }

    while (out_buf_count_ < nsamples) {
      const uint32_t deficit = nsamples - out_buf_count_;
      const uint32_t k = (deficit + ratio_n_ - 1) / ratio_n_;
      const uint32_t to_read = ratio_d_ * k;
      const uint32_t total   = state_len + to_read;

      if (in_buf_cap_ < total) {
        const uint32_t new_cap = std::max(total, in_buf_cap_ * 2);
        for (auto& b : in_buf_)  b.resize(new_cap);
        for (auto& b : new_buf_) b.resize(new_cap);
        in_buf_cap_ = new_cap;
      }

      std::vector<cf_t*> in_buf_ptrs(nports);
      for (uint32_t p = 0; p < nports; p++) {
        in_buf_ptrs[p] = in_buf_[p].data() + state_len;
      }
      int ret = ring_->read(in_buf_ptrs.data(), to_read);
      if (ret < 0) return -1;
      if (static_cast<uint32_t>(ret) < to_read) return -1;

      applyNco(in_buf_, state_len, to_read);

      uint32_t produced = 0;
      for (uint32_t p = 0; p < nports; p++) {
        cf_t* buf = in_buf_[p].data();
        std::copy(state_[p].begin(), state_[p].end(), buf);
        cf_t* filt = new_buf_[p].data();
        for (uint32_t i = 0; i < to_read; i++) {
          filt[i] = srsran_vec_dot_prod_cfc(buf + i, taps_.data(), filter_len_);
        }
        std::copy(buf + total - state_len, buf + total, state_[p].begin());

        int n_out = srsran_resample_arb_compute(
            static_cast<srsran_resample_arb_t*>(resamplers_[p]),
            filt,
            out_buf_[p].data() + out_buf_count_,
            static_cast<int>(to_read));
        if (n_out <= 0) return -1;
        if (p == 0) produced = static_cast<uint32_t>(n_out);
      }
      out_buf_count_ += produced;
    }

    for (uint32_t p = 0; p < nports; p++) {
      std::copy(out_buf_[p].begin(),
                out_buf_[p].begin() + nsamples,
                out[p]);
    }

    const uint32_t leftover = out_buf_count_ - nsamples;
    if (leftover > 0) {
      for (uint32_t p = 0; p < nports; p++) {
        std::copy(out_buf_[p].begin() + nsamples,
                  out_buf_[p].begin() + out_buf_count_,
                  out_buf_[p].begin());
      }
    }
    out_buf_count_ = leftover;
  }

  (void)t;
  return static_cast<int>(nsamples);
}

void DdcChannel::stop() {
  if (ring_) ring_->stop();
}

bool DdcChannel::isStopped() const {
  return ring_ ? ring_->isStopped() : true;
}
