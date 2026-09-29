/*
 * LTESniffer multi-cell refactor — Step 4.
 *
 * See DecimChannel.h for the design.
 */
#include "include/DecimChannel.h"
#include "include/RingBuffer.h"

#include <algorithm>
#include <cmath>
#include <complex>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

DecimChannel::DecimChannel(RingBuffer* ring, uint32_t ratio)
  : ring_(ring),
    ratio_(ratio < 1 ? 1 : ratio)
{
  designFilter();

  const uint32_t nports = ring_->numPorts();
  state_.resize(nports);
  for (auto& s : state_) {
    s.assign(filter_len_ - 1, cf_t{0.0f, 0.0f});
  }
  new_buf_.resize(nports);
}

void DecimChannel::designFilter() {
  // Filter length: 4 * ratio + 1 taps, rounded up to odd for symmetry.
  // For ratio == 1 we still build a 5-tap filter (acts as mild
  // anti-aliasing / DC blocker; harmless).
  filter_len_ = 4 * ratio_ + 1;
  if ((filter_len_ % 2) == 0) filter_len_++;

  // Anti-aliasing cutoff: place the first zero of the sinc at the
  // OUTPUT Nyquist frequency. Normalised to the INPUT sampling rate
  // (where 1.0 == input Nyquist), the output Nyquist is at 1/ratio.
  // Equivalently, normalised to the output rate it is 1.0 (we use the
  // input-rate form because the filter coefficients are applied to
  // input-rate samples).
  const float cutoff = 1.0f / static_cast<float>(ratio_);
  const int   center = static_cast<int>((filter_len_ - 1) / 2);

  taps_.assign(filter_len_, 0.0f);
  float sum = 0.0f;
  for (uint32_t i = 0; i < filter_len_; i++) {
    const float n = static_cast<float>(static_cast<int>(i) - center);
    float sinc_val;
    if (std::fabs(n) < 1e-6f) {
      sinc_val = 1.0f;
    } else {
      const float x = M_PI * cutoff * n;
      sinc_val = std::sin(x) / x;
    }
    // Hamming window
    const float w = 0.54f - 0.46f *
                    std::cos(2.0f * M_PI * static_cast<float>(i) /
                             static_cast<float>(filter_len_ - 1));
    taps_[i] = sinc_val * w;
    sum += taps_[i];
  }
  // Normalise for unity DC gain.
  if (sum != 0.0f) {
    for (auto& t : taps_) t /= sum;
  }
}

int DecimChannel::pull(cf_t* out[SRSRAN_MAX_PORTS],
                        uint32_t nsamples,
                        srsran_timestamp_t* t) {
  if (nsamples == 0) return 0;
  if (isStopped()) return -1;

  // Read enough new samples so the LAST output's filter window
  // (which extends `center` taps past `i*ratio`) stays inside the read
  // buffer. For output sample i=nsamples-1 the highest src_idx is
  // (nsamples-1)*ratio + center = nsamples*ratio - ratio + center.
  // We need nsamples*ratio - ratio + center < to_read, so we add
  // (filter_len_ - 1) extra samples as headroom. This is the standard
  // "read N + filter_len - 1" pattern for FIR filtering.
  const uint32_t to_read = ratio_ * nsamples + (filter_len_ - 1);
  const uint32_t nports  = static_cast<uint32_t>(state_.size());

  // Grow scratch buffer if needed.
  if (new_buf_cap_ < to_read) {
    const uint32_t new_cap = std::max(to_read, new_buf_cap_ * 2);
    for (auto& b : new_buf_) b.resize(new_cap);
    new_buf_cap_ = new_cap;
  }

  // Read `to_read` new samples per port from the ring.
  // new_buf_ is vector<vector<cf_t>>; RingBuffer::read wants cf_t* const*
  // (array of per-port pointers), so build a small scratch array.
  std::vector<cf_t*> new_buf_ptrs(nports);
  for (uint32_t p = 0; p < nports; p++) {
    new_buf_ptrs[p] = new_buf_[p].data();
  }
  int ret = ring_->read(new_buf_ptrs.data(), to_read);
  if (ret < 0) return -1;
  if (static_cast<uint32_t>(ret) < to_read) return -1;

  // Filter + decimate.
  // For each output sample i, the filter window is centred on input
  // sample i*ratio. The window spans [i*ratio - center, i*ratio + center].
  // Negative indices fall back into the per-port state buffer; all
  // non-negative indices are guaranteed to be inside new_buf_ thanks
  // to the extra (filter_len_ - 1) headroom samples read above.
  const int center = static_cast<int>((filter_len_ - 1) / 2);
  const uint32_t state_len = filter_len_ - 1;

  for (uint32_t p = 0; p < nports; p++) {
    cf_t*       dst_p   = out[p];
    const cf_t* new_p   = new_buf_[p].data();
    const cf_t* state_p = state_[p].data();

    for (uint32_t i = 0; i < nsamples; i++) {
      cf_t acc = cf_t{0.0f, 0.0f};
      for (uint32_t k = 0; k < filter_len_; k++) {
        const int src_idx =
            static_cast<int>(i * ratio_) + static_cast<int>(k) - center;
        cf_t sample;
        if (src_idx < 0) {
          // Pull from state (state_len + src_idx is in [0, state_len)).
          sample = state_p[static_cast<uint32_t>(state_len + src_idx)];
        } else {
          // Safe: with the extra (filter_len_ - 1) headroom,
          // src_idx <= (nsamples-1)*ratio + center < to_read.
          sample = new_p[static_cast<uint32_t>(src_idx)];
        }
        acc += sample * cf_t{taps_[k], 0.0f};
      }
      dst_p[i] = acc;
    }
  }

  // Update per-port state: keep the last (filter_len_ - 1) input samples
  // of the new_buf_ stream. (to_read >= state_len always holds here,
  // because to_read = ratio*nsamples + filter_len - 1 >= filter_len - 1.)
  for (uint32_t p = 0; p < nports; p++) {
    std::copy(new_buf_[p].end() - state_len,
              new_buf_[p].end(),
              state_[p].begin());
  }

  // Timestamp: not meaningful after decimation; leave whatever the
  // caller passed in (typically nullptr).
  (void)t;

  return static_cast<int>(nsamples);
}

void DecimChannel::stop() {
  if (ring_) ring_->stop();
}

bool DecimChannel::isStopped() const {
  return ring_ ? ring_->isStopped() : true;
}
