/*
 * LTESniffer multi-cell refactor — Step 2.
 *
 * CellPipeline implementation. The body is a faithful extraction of
 * the legacy LTESniffer_Core::run() inner section (init ue_sync/ue_mib
 * → main loop → cleanup). No decode logic is changed.
 */
#include "include/CellPipeline.h"
#include "include/LTESniffer_Core.h"  // srsran_rf_set_rx_gain_th_wrapper_

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>

using namespace std;

// srsRAN fork ShaoPaoLao/srsRAN2 does not provide
// srsran_chest_dl_str2estimator_alg(). Provide a local equivalent that
// accepts the same string forms ("average", "interpolate", "wiener").
static srsran_chest_dl_estimator_alg_t srsran_chest_dl_str2estimator_alg_local(const char* s) {
  if (s == nullptr) return SRSRAN_ESTIMATOR_ALG_AVERAGE;
  std::string str(s);
  if (str == "average")    return SRSRAN_ESTIMATOR_ALG_AVERAGE;
  if (str == "interpolate") return SRSRAN_ESTIMATOR_ALG_INTERPOLATE;
  if (str == "wiener")     return SRSRAN_ESTIMATOR_ALG_WIENER;
  return SRSRAN_ESTIMATOR_ALG_AVERAGE;
}

CellPipeline::CellPipeline(const Args& args,
                           ISampleSource* sample_source,
                           const srsran_cell_t& cell,
                           int sniffer_mode,
                           int api_mode,
                           bool legacy_pcap_name)
  : args_(args),
    sample_source_(sample_source),
    cell_(cell),
    sniffer_mode_(sniffer_mode),
    api_mode_(api_mode),
    legacy_pcap_name_(legacy_pcap_name),
    state_(DECODE_MIB),
    phy_(nullptr),
    mcs_tracking_(args.mcs_tracking_mode, args.target_rnti, args.en_debug,
                  sniffer_mode, api_mode, est_cfo_),
    ulsche_(args.target_rnti, &ul_harq_, args.en_debug),
    mcs_tracking_mode_(args.mcs_tracking_mode),
    harq_mode_(args.harq_mode)
{
  // Tag this pipeline's MCSTracking with its cell PCI so the per-RNTI
  // tables it prints are unambiguously labelled in multi-cell mode.
  // Must be set before the first print_database_*() call.
  mcs_tracking_.setPCI(cell_.id);
  cell_init_ = cell_;

  // ---- pcap file name ----
  std::string pcap_file_name;
  std::string pcap_file_name_api = "api_collector.pcap";
  if (legacy_pcap_name_) {
    // Legacy single-cell filenames (preserved for N==1 regression).
    pcap_file_name = (sniffer_mode_ == DL_MODE)
                       ? "ltesniffer_dl_mode.pcap"
                       : "ltesniffer_ul_mode.pcap";
  } else {
    // Per-cell filename so concurrent pipelines don't clobber each other.
    const char* mode_str = (sniffer_mode_ == DL_MODE) ? "dl" : "ul";
    char buf[128];
    std::snprintf(buf, sizeof(buf), "ltesniffer_%s_cell%u.pcap",
                  mode_str, cell_.id);
    pcap_file_name = buf;
  }
  pcapwriter_.open(pcap_file_name, pcap_file_name_api, 0);

  // ---- HARQ ----
  harq_.init_HARQ(args_.harq_mode);

  // ---- UL schedule ----
  ulsche_.set_multi_offset(sniffer_mode_);

  // ---- PHY (worker pool) ----
  phy_ = new Phy(args_.rf_nof_rx_ant,
                 args_.nof_sniffer_thread,
                 args_.dci_file_name,
                 args_.stats_file_name,
                 args_.skip_secondary_meta_formats,
                 args_.dci_format_split_ratio,
                 args_.rnti_histogram_threshold,
                 &pcapwriter_,
                 &mcs_tracking_,
                 &harq_,
                 args_.mcs_tracking_mode,
                 args_.harq_mode,
                 &ulsche_);
  phy_->getCommon().setShortcutDiscovery(args_.enable_shortcut_discovery);

  std::shared_ptr<DCIConsumerList> cons(new DCIConsumerList());
  if (args_.dci_file_name != "") {
    cons->addConsumer(static_pointer_cast<SubframeInfoConsumer>(
        std::shared_ptr<DCIToFile>(new DCIToFile(phy_->getCommon().getDCIFile()))));
  }
  // ASCII plots intentionally disabled (matches legacy behaviour).
  phy_->getCommon().setDCIConsumer(cons);

  // ---- TA buffer (UL timing advance) ----
  ta_buffer_.ta_temp_buffer = static_cast<cf_t*>(
      srsran_vec_malloc(3 * sizeof(cf_t) * SRSRAN_SF_LEN_PRB(100)));
  for (int i = 0; i < 100; i++) {
    ta_buffer_.ta_last_sample[i] = 0;
  }
}

CellPipeline::~CellPipeline() {
  pcapwriter_.close();
  // phy_ is intentionally not deleted here: it owns threads that must be
  // joined before destruction. joinPending() in run() handles that.
  printf("Deleted CellPipeline\n");
}

void CellPipeline::startAgc(double min_rx_gain, double max_rx_gain, double init_agc) {
  srsran_ue_sync_start_agc(&ue_sync_,
                           srsran_rf_set_rx_gain_th_wrapper_,
                           min_rx_gain,
                           max_rx_gain,
                           init_agc);
}

void CellPipeline::initUeSyncRf() {
  int decimate = 0;
  if (args_.decimate) {
    if (args_.decimate > 4 || args_.decimate < 0) {
      printf("Invalid decimation factor, setting to 1 \n");
    } else {
      decimate = args_.decimate;
    }
  }
  if (srsran_ue_sync_init_multi_decim(&ue_sync_,
                                      cell_.nof_prb,
                                      cell_.id == 1000,
                                      sample_source_recv_wrapper,
                                      args_.rf_nof_rx_ant,
                                      (void*)sample_source_,
                                      decimate)) {
    ERROR("Error initiating ue_sync");
    exit(-1);
  }
  if (srsran_ue_sync_set_cell(&ue_sync_, cell_)) {
    ERROR("Error initiating ue_sync");
    exit(-1);
  }
}

void CellPipeline::initUeSyncFile() {
  char* tmp_filename = new char[args_.input_file_name.length() + 1];
  strncpy(tmp_filename, args_.input_file_name.c_str(), args_.input_file_name.length());
  tmp_filename[args_.input_file_name.length()] = 0;
  if (srsran_ue_sync_init_file_multi(&ue_sync_,
                                     args_.nof_prb,
                                     tmp_filename,
                                     args_.file_offset_time,
                                     args_.file_offset_freq,
                                     args_.rf_nof_rx_ant)) {
    ERROR("Error initiating ue_sync");
    exit(-1);
  }
  delete[] tmp_filename;
  tmp_filename = nullptr;
}

void CellPipeline::initUeMib(cf_t* buffer) {
  if (srsran_ue_mib_init(&ue_mib_, buffer, cell_.nof_prb)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }
  if (srsran_ue_mib_set_cell(&ue_mib_, cell_)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }
}

void CellPipeline::configureCfo(float search_cell_cfo) {
  // Disable CP based CFO estimation during find
  ue_sync_.cfo_current_value       = search_cell_cfo / 15000;
  ue_sync_.cfo_is_copied           = true;
  ue_sync_.cfo_correct_enable_find = true;
  srsran_sync_set_cfo_cp_enable(&ue_sync_.sfind, false, 0);
  ue_sync_.cfo_correct_enable_track = !args_.disable_cfo;
  srsran_pbch_decode_reset(&ue_mib_.pbch);
}

void CellPipeline::configurePdsch() {
  ZERO_OBJECT(dl_sf_);
  ZERO_OBJECT(pdsch_cfg_);
  pdsch_cfg_.meas_evm_en = true;
  srsran_chest_dl_cfg_t chest_pdsch_cfg = {};
  chest_pdsch_cfg.cfo_estimate_enable   = args_.enable_cfo_ref;
  chest_pdsch_cfg.cfo_estimate_sf_mask  = 1023;
  chest_pdsch_cfg.estimator_alg         =
      srsran_chest_dl_str2estimator_alg_local(args_.estimator_alg.c_str());
  chest_pdsch_cfg.sync_error_enable     = true;
}

void CellPipeline::setupRntiManager() {
  RNTIManager& rntiManager = phy_->getCommon().getRNTIManager();
  int idx;
  idx = falcon_dci_index_of_format_in_list(SRSRAN_DCI_FORMAT1A,
                                           falcon_ue_all_formats,
                                           nof_falcon_ue_all_formats);
  if (idx > -1) {
    rntiManager.addEvergreen(SRSRAN_RARNTI_START, SRSRAN_RARNTI_END,
                             static_cast<uint32_t>(idx));
    rntiManager.addEvergreen(SRSRAN_PRNTI, SRSRAN_SIRNTI,
                             static_cast<uint32_t>(idx));
  }
  idx = falcon_dci_index_of_format_in_list(SRSRAN_DCI_FORMAT1C,
                                           falcon_ue_all_formats,
                                           nof_falcon_ue_all_formats);
  if (idx > -1) {
    rntiManager.addEvergreen(SRSRAN_RARNTI_START, SRSRAN_RARNTI_END,
                             static_cast<uint32_t>(idx));
    rntiManager.addEvergreen(SRSRAN_PRNTI, SRSRAN_SIRNTI,
                             static_cast<uint32_t>(idx));
  }
  for (uint32_t f = 0; f < nof_falcon_ue_all_formats; f++) {
    rntiManager.addForbidden(0x0, 0x0, f);
  }
}

void CellPipeline::printApiHeader() {
  for (int i = 0; i < 90; i++) std::cout << "-";
  std::cout << std::endl;
  std::cout << std::left << std::setw(10)  << "SF";
  std::cout << std::left << std::setw(26) << "Detected Identity";
  std::cout << std::left << std::setw(17) << "Value";
  std::cout << std::left << std::setw(11) << "RNTI";
  std::cout << std::left << std::setw(25) << "From Message";
  std::cout << std::endl;
  for (int i = 0; i < 90; i++) std::cout << "-";
  std::cout << std::endl;
}

void CellPipeline::stop() {
  go_exit_.store(true, std::memory_order_release);
  if (sample_source_) sample_source_->stop();
}

bool CellPipeline::run() {
  // ---- 1. ue_sync init (file or RF) ----
  if (args_.input_file_name != "") {
    initUeSyncFile();
  } else {
#ifndef DISABLE_RF
    initUeSyncRf();
#endif
  }

  // ---- 2. set cell on every SubframeWorker ----
  if (!phy_->setCell(cell_)) {
    cout << "Error initiating UE downlink processing module" << endl;
    return true;
  }

  // ---- 3. grab first worker, init ue_mib on its buffer ----
  std::shared_ptr<SubframeWorker> cur_worker(phy_->getAvail());
  cf_t** cur_buffer = cur_worker->getBuffers();
  initUeMib(cur_buffer[0]);

  // ---- 4. CFO + PDSCH config ----
  // search_cell_cfo is unknown here; pass 0 (legacy code only used it
  // when cell search was enabled, and even then the value was applied
  // identically — see configureCfo).
  configureCfo(0.0f);
  configurePdsch();

  // ---- 5. main loop ----
  uint32_t sfn = 0;
  uint32_t skip_cnt = 0;
  uint32_t total_sf = 0;
  uint32_t skip_last_1s = 0;
  uint16_t nof_lost_sync = 0;
  int mcs_tracking_timer = 0;
  int update_rnti_timer = 0;
  uint64_t sf_cnt = 0;
  int ret, n;

  // Length in complex samples — per-cell (INVARIANT).
  uint32_t max_num_samples = 3 * SRSRAN_SF_LEN_PRB(cell_.nof_prb);

  while (!go_exit_.load(std::memory_order_acquire) &&
         (sf_cnt < args_.nof_subframes || args_.nof_subframes == 0)) {

    set_srsran_verbose_level(args_.verbose);
    ret = srsran_ue_sync_zerocopy(&ue_sync_, cur_worker->getBuffers(),
                                  max_num_samples);
    if (ret < 0) {
      if (args_.input_file_name != "") {
        std::cout << "Finish reading from file" << std::endl;
      }
      ERROR("Error calling srsran_ue_sync_work()");
    }

    if (ret == 1) {
      uint32_t sf_idx = srsran_ue_sync_get_sfidx(&ue_sync_);
      switch (state_) {
        case DECODE_MIB:
          if (sf_idx == 0) {
            uint8_t bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
            int     sfn_offset;
            n = srsran_ue_mib_decode(&ue_mib_, bch_payload, NULL, &sfn_offset);
            if (n < 0) {
              ERROR("Error decoding UE MIB");
              exit(-1);
            } else if (n == SRSRAN_UE_MIB_FOUND) {
              // Unpack into a scratch copy for inspection only. The user's
              // configured PRB (--cells PCI:PRB) is authoritative: the whole
              // sample path (capture rate, ring, channel decimation) was
              // built around it. A marginal PBCH can also pass CRC with
              // garbage bits, so MIB never overwrites cell_.
              srsran_cell_t unpacked = cell_;
              srsran_pbch_mib_unpack(bch_payload, &unpacked, &sfn);
              if (srsran_nofprb_isvalid(unpacked.nof_prb)) {
                if (unpacked.nof_prb != cell_.nof_prb) {
                  printf("MIB reports PRB=%u but configured PRB=%u — keeping configured value\n",
                         unpacked.nof_prb, cell_.nof_prb);
                }
                srsran_cell_fprint(stdout, &cell_, sfn);
                printf("Decoded MIB. SFN: %d, offset: %d\n", sfn, sfn_offset);
                sfn = (sfn + sfn_offset) % 1024;
                state_ = DECODE_PDSCH;
                setupRntiManager();
              } else {
                printf("Discarding bogus MIB (nof_prb=%u) - PBCH false positive\n",
                       unpacked.nof_prb);
                srsran_pbch_decode_reset(&ue_mib_.pbch);
              }
            }
          }
          break;
        case DECODE_PDSCH:
          if ((mcs_tracking_.get_nof_api_msg() % 30) == 0 && api_mode_ > -1) {
            printApiHeader();
            mcs_tracking_.increase_nof_api_msg();
            if (mcs_tracking_.get_nof_api_msg() > 30) {
              mcs_tracking_.reset_nof_api_msg();
            }
          }
          {
            uint32_t tti = sfn * 10 + sf_idx;
            dl_sf_.tti = tti;
            dl_sf_.sf_type = SRSRAN_SF_NORM;
            cur_worker->prepare(sf_idx, sfn,
                                sf_cnt % args_.dci_format_split_update_interval_ms == 0,
                                dl_sf_);

            std::shared_ptr<SubframeWorker> next_worker;
            if (args_.input_file_name == "") {
              next_worker = phy_->getAvailImmediate();
            } else {
              next_worker = phy_->getAvail();
            }
            if (next_worker != nullptr) {
              phy_->putPending(std::move(cur_worker));
              cur_worker = std::move(next_worker);
            } else {
              skip_cnt++;
              skip_last_1s++;
            }
          }
          break;
      }

      if (sf_idx == 9) sfn++;
      if (sfn == 1024) sfn = 0;
      total_sf++;

      if ((total_sf % 1000) == 0 && (api_mode_ == -1)) {
        auto now = std::chrono::system_clock::now();
        std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
        std::string str_cur_time(std::ctime(&cur_time));
        std::string cur_time_second = str_cur_time.substr(11, 8);
        std::cout << "[" << cur_time_second << "] Processed "
                  << (1000 - skip_last_1s) << "/1000 subframes" << "\n";
        mcs_tracking_timer++;
        update_rnti_timer++;
        skip_last_1s = 0;
      }
      if (update_rnti_timer == (int)mcs_tracking_.get_interval()) {
        switch (sniffer_mode_) {
          case DL_MODE:
            if (mcs_tracking_mode_ && args_.target_rnti == 0)
              mcs_tracking_.update_database_dl();
            break;
          case UL_MODE:
            if (mcs_tracking_mode_) mcs_tracking_.update_database_ul();
            break;
          default: break;
        }
        update_rnti_timer = 0;
      }
      if (mcs_tracking_timer == 10) {
        switch (sniffer_mode_) {
          case DL_MODE:
            if (api_mode_ == -1) mcs_tracking_.print_database_dl();
            if (mcs_tracking_mode_ && args_.target_rnti == 0)
              mcs_tracking_.update_database_dl();
            if (harq_mode_ && args_.target_rnti == 0)
              harq_.updateHARQDatabase();
            mcs_tracking_timer = 0;
            break;
          case UL_MODE:
            if (api_mode_ == -1) mcs_tracking_.print_database_ul();
            if (mcs_tracking_mode_) mcs_tracking_.update_database_ul();
            mcs_tracking_timer = 0;
            break;
          default: break;
        }
      }
    } else if (ret == 0) {
      if (state_ == DECODE_PDSCH && nof_lost_sync > 5) {
        state_ = DECODE_MIB;
        if (!srsran_nofprb_isvalid(cell_.nof_prb)) {
          // Defence in depth: repair any corrupted cell config before re-init.
          cell_ = cell_init_;
        }
        if (srsran_ue_mib_init(&ue_mib_, cur_worker->getBuffers()[0],
                               cell_.nof_prb)) {
          ERROR("Error initaiting UE MIB decoder");
          exit(-1);
        }
        if (srsran_ue_mib_set_cell(&ue_mib_, cell_)) {
          ERROR("Error initaiting UE MIB decoder");
          exit(-1);
        }
        srsran_pbch_decode_reset(&ue_mib_.pbch);
        nof_lost_sync = 0;
      }
      nof_lost_sync++;
      cout << "Finding PSS... Peak: " << srsran_sync_get_peak_value(&ue_sync_.sfind)
           << ", FrameCnt: " << ue_sync_.frame_total_cnt
           << " State: " << ue_sync_.state << endl;
    }
    sf_cnt++;
  }

  // ---- 6. final stats ----
  if (mcs_tracking_mode_) {
    switch (sniffer_mode_) {
      case DL_MODE:
        mcs_tracking_.merge_all_database_dl();
        if (api_mode_ == -1) mcs_tracking_.print_all_database_dl();
        break;
      case UL_MODE:
        mcs_tracking_.merge_all_database_ul();
        if (api_mode_ == -1) mcs_tracking_.print_all_database_ul();
        break;
      default: break;
    }
  }

  phy_->joinPending();
  std::cout << "Destroyed Phy" << std::endl;

  if (args_.input_file_name == "") {
    srsran_ue_sync_free(&ue_sync_);
    srsran_ue_mib_free(&ue_mib_);
  }

  cout << "Skipped subframe: " << skip_cnt << " / " << sf_cnt << endl;
  phy_->getCommon().printStats();
  cout << "Skipped subframes: " << skip_cnt << " ("
       << static_cast<double>(skip_cnt) * 100 /
          (phy_->getCommon().getStats().nof_subframes + skip_cnt)
       << "%)" << endl;

  return EXIT_SUCCESS;
}
