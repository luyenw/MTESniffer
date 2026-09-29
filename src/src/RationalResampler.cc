/*
 * LTESniffer multi-cell refactor — Step 5.
 *
 * See RationalResampler.h for the design.
 */
#include "include/RationalResampler.h"
#include "include/RingBuffer.h"

#include <algorithm>
#include <complex>
#include <memory>

// C++11 polyfill for std::make_unique (C++14 feature).
#if __cplusplus < 201402L
namespace std {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
#endif

RationalResampler::RationalResampler(RingBuffer* ring,
                                     uint32_t max_prb,
                                     uint32_t cell_prb)
  : ring_(ring),
    max_prb_(max_prb),
    cell_prb_(cell_prb),
    ratio_n_(cell_prb),
    ratio_d_(max_prb),
    ratio_(static_cast<float>(cell_prb) / static_cast<float>(max_prb))
{
  const uint32_t nports = ring_->numPorts();
  in_buf_.resize(nports);
  out_buf_.resize(nports);
  resamplers_.reserve(nports);

  // srsran_resample_arb is a POD struct with no allocation; we just
  // need one per port. If init fails partway through, the partial
  // vector is destroyed by RAII (no leak — POD has no destructor).
  for (uint32_t p = 0; p < nports; p++) {
    auto r = std::make_unique<srsran_resample_arb_t>();
    // rate = output_rate / input_rate = cell_prb / max_prb
    // interpolate=true because cell_prb < max_prb (we are downsampling
    // in the polyphase sense; the polyphase filter still interpolates
    // internally and then we take every Nth output).
    srsran_resample_arb_init(r.get(), ratio_, /*interpolate=*/true);
    resamplers_.push_back(std::move(r));
  }
  resamplers_ok_ = true;
}

RationalResampler::~RationalResampler() {
  // unique_ptr handles destruction of POD structs automatically.
}

int RationalResampler::pull(cf_t* out[SRSRAN_MAX_PORTS],
                            uint32_t nsamples,
                            srsran_timestamp_t* t) {
  if (nsamples == 0) return 0;
  if (isStopped()) return -1;
  if (!resamplers_ok_) return -1;

  const uint32_t nports = static_cast<uint32_t>(in_buf_.size());

  // Ensure output buffer can hold nsamples plus enough headroom for
  // srsran_resample_arb's filter delay. The resampler may produce up to
  // `ratio_n_ * k + filter_delay` samples per call; with k up to
  // ceil(nsamples/ratio_n_) the worst case is roughly
  // `nsamples + ratio_n_ + filter_delay`. We allocate `2 * ratio_n_`
  // of headroom to be safe.
  const uint32_t needed_out = nsamples + 2 * ratio_n_;
  if (out_buf_cap_ < needed_out) {
    const uint32_t new_cap = std::max(needed_out, out_buf_cap_ * 2);
    for (auto& b : out_buf_) b.resize(new_cap);
    out_buf_cap_ = new_cap;
  }

  // Accumulate output until we have at least nsamples.
  while (out_buf_count_ < nsamples) {
    // How many input chunks do we need?
    // Each chunk of `ratio_d_` input samples yields ~`ratio_n_` output
    // samples. We round up so we never under-shoot.
    const uint32_t deficit = nsamples - out_buf_count_;
    const uint32_t k = (deficit + ratio_n_ - 1) / ratio_n_;
    const uint32_t to_read = ratio_d_ * k;

    // Grow input buffer if needed.
    if (in_buf_cap_ < to_read) {
      const uint32_t new_cap = std::max(to_read, in_buf_cap_ * 2);
      for (auto& b : in_buf_) b.resize(new_cap);
      in_buf_cap_ = new_cap;
    }

    // Read from ring. in_buf_ is vector<vector<cf_t>>; RingBuffer::read
    // wants cf_t* const* (array of per-port pointers).
    std::vector<cf_t*> in_buf_ptrs(nports);
    for (uint32_t p = 0; p < nports; p++) {
      in_buf_ptrs[p] = in_buf_[p].data();
    }
    int ret = ring_->read(in_buf_ptrs.data(), to_read);
    if (ret < 0) return -1;
    if (static_cast<uint32_t>(ret) < to_read) return -1;

    // Resample each port. srsran_resample_arb_compute is single-port
    // and returns the number of output samples produced.
    uint32_t produced = 0;
    for (uint32_t p = 0; p < nports; p++) {
      int n_out = srsran_resample_arb_compute(resamplers_[p].get(),
                                              in_buf_[p].data(),
                                              out_buf_[p].data() + out_buf_count_,
                                              static_cast<int>(to_read));
      if (n_out < 0) return -1;
      if (n_out == 0) {
        // Resampler produced nothing — should not happen for a valid
        // rational ratio with non-zero input. Bail out to avoid an
        // infinite loop.
        return -1;
      }
      if (p == 0) {
        produced = static_cast<uint32_t>(n_out);
      }
      // For p > 0 we trust the resampler to be deterministic and
      // produce the same count as port 0.
    }
    out_buf_count_ += produced;
  }

  // Copy nsamples output samples to the caller's buffer.
  for (uint32_t p = 0; p < nports; p++) {
    std::copy(out_buf_[p].begin(),
              out_buf_[p].begin() + nsamples,
              out[p]);
  }

  // Shift the leftover to the front of the output buffer.
  const uint32_t leftover = out_buf_count_ - nsamples;
  if (leftover > 0) {
    for (uint32_t p = 0; p < nports; p++) {
      std::copy(out_buf_[p].begin() + nsamples,
                out_buf_[p].begin() + out_buf_count_,
                out_buf_[p].begin());
    }
  }
  out_buf_count_ = leftover;

  (void)t;
  return static_cast<int>(nsamples);
}

void RationalResampler::stop() {
  if (ring_) ring_->stop();
}

bool RationalResampler::isStopped() const {
  return ring_ ? ring_->isStopped() : true;
}
