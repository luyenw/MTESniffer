/*
 * LTESniffer multi-cell refactor — Step 3.
 */
#include "include/WidebandCapture.h"
#include "include/RingBuffer.h"

#include <cstring>
#include <iostream>

WidebandCapture::WidebandCapture(ISampleSource* source, uint32_t block_samples)
  : source_(source), block_samples_(block_samples) {
  scratch_.resize(SRSRAN_MAX_PORTS);
  for (auto& s : scratch_) {
    s.assign(block_samples_, cf_t{0.0f, 0.0f});
  }
}

WidebandCapture::~WidebandCapture() {
  stop();
}

void WidebandCapture::registerSink(RingBuffer* sink) {
  if (sink != nullptr) sinks_.push_back(sink);
}

bool WidebandCapture::start() {
  if (running_.load(std::memory_order_acquire)) return false;
  if (sinks_.empty()) {
    std::cerr << "WidebandCapture: no sinks registered, refusing to start\n";
    return false;
  }
  if (source_ == nullptr) {
    std::cerr << "WidebandCapture: null source, refusing to start\n";
    return false;
  }
  stop_requested_.store(false, std::memory_order_release);
  running_.store(true, std::memory_order_release);
  thread_ = std::thread([this] { runLoop(); });
  return true;
}

void WidebandCapture::stop() {
  if (!running_.load(std::memory_order_acquire)) return;
  stop_requested_.store(true, std::memory_order_release);
  if (source_) source_->stop();
  // Also stop all registered rings so any blocked readers wake up.
  // Without this, downstream channels would block forever waiting for
  // samples that will never arrive (because the capture is gone).
  for (auto* sink : sinks_) {
    if (sink) sink->stop();
  }
  if (thread_.joinable()) thread_.join();
  running_.store(false, std::memory_order_release);
}

void WidebandCapture::runLoop() {
  // Build the per-port pointer array once.
  cf_t* scratch_ptrs[SRSRAN_MAX_PORTS];
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    scratch_ptrs[i] = scratch_[i].data();
  }

  while (!stop_requested_.load(std::memory_order_acquire)) {
    int n = source_->pull(scratch_ptrs, block_samples_, nullptr);
    if (n < 0) break;  // source stopped
    if (static_cast<uint32_t>(n) != block_samples_) {
      // Partial block — still broadcast what we got.
      // (srsran_rf_recv_with_time_multi normally returns the requested
      //  count or an error; partial reads are rare but possible.)
    }
    const uint32_t got = static_cast<uint32_t>(n);
    for (auto* sink : sinks_) {
      if (sink) sink->write(const_cast<const cf_t**>(scratch_ptrs), got);
    }
  }
}
