#pragma once

#include <stdint.h>
#include <atomic>
#include "falcon/util/RNTIManager.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"
#include "SubframeInfoConsumer.h"

extern const srsran_dci_format_t falcon_ue_all_formats[];
extern const uint32_t nof_falcon_ue_all_formats;

class DCIBlindSearchStats {
public:
    DCIBlindSearchStats();
    void print(FILE* file);
    DCIBlindSearchStats& operator+=(const DCIBlindSearchStats& right);

    uint32_t nof_locations;
    uint32_t nof_decoded_locations;
    uint32_t nof_cce;
    uint32_t nof_missed_cce;
    uint32_t nof_subframes;
    uint32_t nof_subframe_collisions_dw;
    uint32_t nof_subframe_collisions_up;
    struct timeval time_blindsearch;
};

class PhyStats {
public:
    PhyStats();
    ~PhyStats();
    PhyStats& operator+=(const PhyStats& right);

    uint32_t totRBup, totRBdw, totBWup, totBWdw;
    uint16_t nof_rnti;
};

class PhyCommon {
public:
  PhyCommon(uint32_t max_prb,
            uint32_t nof_rx_antennas,
            const std::string& dciFileName,
            const std::string& statsFileName,
            uint32_t histogramThreshold);
  ~PhyCommon();
  RNTIManager& getRNTIManager();
  FILE* getDCIFile();
  FILE* getStatsFile();
  void addStats(const DCIBlindSearchStats& stats);
  DCIBlindSearchStats& getStats();
  void printStats();

  void setShortcutDiscovery(bool enable);
  bool getShortcutDiscovery() const;

  //upper layer interfaces
  void setDCIConsumer(std::shared_ptr<SubframeInfoConsumer>);
  void resetDCIConsumer();

  //lower layer interface
  void consumeDCICollection(const SubframeInfo& subframeInfo);

  // SIB1 PLMN, reported by any worker, read by CellPipeline (MCC/MNC filter).
  void reportSib1Plmn(uint16_t mcc, uint16_t mnc) {
    if (sib1_ready.load(std::memory_order_acquire)) return;
    sib1_plmn.store((static_cast<uint32_t>(mcc) << 16) | mnc, std::memory_order_relaxed);
    sib1_ready.store(true, std::memory_order_release);
  }
  bool getSib1Plmn(uint16_t& mcc, uint16_t& mnc) const {
    if (!sib1_ready.load(std::memory_order_acquire)) return false;
    const uint32_t v = sib1_plmn.load(std::memory_order_relaxed);
    mcc = static_cast<uint16_t>(v >> 16);
    mnc = static_cast<uint16_t>(v & 0xFFFF);
    return true;
  }

  uint32_t max_prb;
  uint32_t nof_rx_antennas;
private:
  std::atomic<bool>     sib1_ready{false};
  std::atomic<uint32_t> sib1_plmn{0};

  FILE* dci_file;
  FILE* stats_file;
  RNTIManager rntiManager;

  DCIBlindSearchStats stats;

  std::shared_ptr<DCIToFile> defaultDCIConsumer;
  std::shared_ptr<SubframeInfoConsumer> dciConsumer;

  bool enableShortcutDiscovery;
};
