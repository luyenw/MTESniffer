/*
 * LTESniffer multi-cell refactor — Step 3.
 */
#include "include/FileSampleSource.h"

#include <cstring>
#include <vector>

FileSampleSource::FileSampleSource(const std::string& path, uint32_t nof_ports)
  : fp_(std::fopen(path.c_str(), "rb")), nof_ports_(nof_ports) {}

FileSampleSource::~FileSampleSource() {
  if (fp_) std::fclose(fp_);
}

int FileSampleSource::pull(cf_t* out[SRSRAN_MAX_PORTS],
                           uint32_t nsamples,
                           srsran_timestamp_t* /* t */) {
  if (stopped_.load(std::memory_order_acquire) || fp_ == nullptr) return -1;

  std::vector<cf_t> tmp(nsamples);
  for (uint32_t p = 0; p < nof_ports_; p++) {
    if (out[p] == nullptr) continue;
    size_t got = std::fread(tmp.data(), sizeof(cf_t), nsamples, fp_);
    if (got == 0) return -1;  // EOF
    std::memcpy(out[p], tmp.data(), got * sizeof(cf_t));
    if (got < nsamples) {
      // Zero-pad the rest of this port and short-return.
      std::memset(out[p] + got, 0, (nsamples - got) * sizeof(cf_t));
    }
  }
  return static_cast<int>(nsamples);
}

void FileSampleSource::stop() {
  stopped_.store(true, std::memory_order_release);
}
