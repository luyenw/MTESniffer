/*
 * LTESniffer multi-cell refactor — Step 3.
 *
 * RingBuffer implementation. See RingBuffer.h for the contract.
 */
#include "include/RingBuffer.h"

#include <cstring>  // memcpy

RingBuffer::RingBuffer(uint32_t nof_ports, uint32_t capacity)
  : nof_ports_(nof_ports), capacity_(capacity) {
  buffers_.resize(nof_ports_);
  for (auto& b : buffers_) {
    b.assign(capacity_, cf_t{0.0f, 0.0f});
  }
}

void RingBuffer::write(const cf_t* const* src, uint32_t n) {
  if (n == 0 || stopped_.load(std::memory_order_acquire)) return;

  std::lock_guard<std::mutex> wlk(write_mutex_);

  const uint64_t w = write_count_.load(std::memory_order_relaxed);
  const uint64_t r = read_count_.load(std::memory_order_acquire);

  // If the ring would overflow, advance read_count_ to make room.
  // (Both indices are monotonic, so this is safe even if the reader
  //  is concurrently reading — at worst the reader sees slightly stale
  //  data and skips it on the next iteration.)
  const uint64_t used = (w >= r) ? (w - r) : 0;
  if (used + n > capacity_) {
    const uint64_t drop = used + n - capacity_;
    read_count_.fetch_add(drop, std::memory_order_release);
    drop_count_.fetch_add(drop, std::memory_order_release);
  }

  // Copy n samples per port into the ring at offset (w % capacity_).
  // Handle wrap-around with two memcpys.
  const uint32_t cap = capacity_;
  const uint32_t start = static_cast<uint32_t>(w % cap);
  for (uint32_t p = 0; p < nof_ports_; p++) {
    if (src[p] == nullptr) continue;
    if (start + n <= cap) {
      std::memcpy(buffers_[p].data() + start, src[p], n * sizeof(cf_t));
    } else {
      const uint32_t first = cap - start;
      std::memcpy(buffers_[p].data() + start, src[p], first * sizeof(cf_t));
      std::memcpy(buffers_[p].data(), src[p] + first, (n - first) * sizeof(cf_t));
    }
  }

  write_count_.fetch_add(n, std::memory_order_release);

  // Wake any reader waiting for data.
  read_cv_.notify_one();
}

int RingBuffer::read(cf_t* const* dst, uint32_t n) {
  if (n == 0) return 0;

  std::unique_lock<std::mutex> rlk(read_mutex_);

  // Wait until we have n samples available, or stop() is called.
  read_cv_.wait(rlk, [this, n] {
    if (stopped_.load(std::memory_order_acquire)) return true;
    const uint64_t w = write_count_.load(std::memory_order_acquire);
    const uint64_t r = read_count_.load(std::memory_order_relaxed);
    return (w - r) >= n;
  });

  if (stopped_.load(std::memory_order_acquire)) {
    return -1;
  }

  const uint64_t r = read_count_.load(std::memory_order_relaxed);
  const uint32_t cap = capacity_;
  const uint32_t start = static_cast<uint32_t>(r % cap);

  for (uint32_t p = 0; p < nof_ports_; p++) {
    if (dst[p] == nullptr) continue;
    if (start + n <= cap) {
      std::memcpy(dst[p], buffers_[p].data() + start, n * sizeof(cf_t));
    } else {
      const uint32_t first = cap - start;
      std::memcpy(dst[p], buffers_[p].data() + start, first * sizeof(cf_t));
      std::memcpy(dst[p] + first, buffers_[p].data(), (n - first) * sizeof(cf_t));
    }
  }

  read_count_.fetch_add(n, std::memory_order_release);
  return static_cast<int>(n);
}

void RingBuffer::stop() {
  {
    std::lock_guard<std::mutex> rlk(read_mutex_);
    stopped_.store(true, std::memory_order_release);
  }
  read_cv_.notify_all();
}
