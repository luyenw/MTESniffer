#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include "Sniffer_dependency.h"

/*
 * Step 3 (multi-cell refactor): one entry per cell to be sniffed.
 * Step 3b (case 3b): each cell may have its own DL EARFCN. If dl_earfcn == 0
 * the cell inherits the global -f DL EARFCN (legacy same-EARFCN behaviour).
 */
struct CellCfg {
  uint32_t dl_earfcn;  // 0 = use global -f DL EARFCN
  uint32_t pci;        // Physical Cell ID (0..503)
  uint32_t nof_prb;    // 6, 15, 25, 50, 75, 100; 0 = auto-detect from MIB
};

struct Args {
  // No pointer members! Avoid shallow copies
  uint32_t    nof_subframes;
  int         cpu_affinity;
  bool        enable_ASCII_PRB_plot;
  bool        enable_ASCII_power_plot;
  bool        disable_cfo;
  uint32_t    time_offset;
  int         force_N_id_2;
  std::string input_file_name = "";
  std::string dci_file_name = "";
  std::string stats_file_name = "";
  int         file_offset_time;
  double      file_offset_freq;
  uint32_t    nof_prb;
  uint32_t    file_nof_prb;
  uint32_t    file_nof_ports;
  uint32_t    file_cell_id;
  bool        file_wrap;
  std::string rf_args;
  uint32_t    rf_nof_rx_ant;
  double      rf_freq;
  double      rf_gain;
  int         decimate;
  int         nof_sniffer_thread;
  uint32_t    cell_id = 0;
  double      ul_freq = 0;
  int         sniffer_mode = DL_MODE;
  bool        en_debug = false;

  // other config args
  uint32_t    dci_format_split_update_interval_ms;
  double      dci_format_split_ratio;
  bool        skip_secondary_meta_formats;
  bool        enable_shortcut_discovery;
  uint32_t    rnti_histogram_threshold;
  std::string pcap_file;
  int         harq_mode;
  uint16_t    rnti;
  int         mcs_tracking_mode;
  int         verbose;
  char*       rf_dev;
  //char* rf_args;
  int         enable_cfo_ref;
  std::string estimator_alg;
  bool        cell_search = false;
  uint16_t    target_rnti = 0;
  int         api_mode    = -1; //api functions, 0: identity mapping, 1: UECapa, 2: IMSI

  // Step 3: multi-cell list. Empty => legacy single-cell path.
  std::vector<CellCfg> cells;

  // Step 3b (case 3b): pre-flight / multi-EARFCN options.
  bool   force        = false;  // --force: proceed on GO_WITH_WARN
  double guard_hz     = 200e3;  // --guard-hz: transition-band guard
  bool   cells_have_dl_earfcn = false;  // true if --cells given (DL_EARFCN:PCI[:PRB] form)

  // MCC/MNC filter (optional). If set, only cells matching MCC/MNC are sniffed.
  // 0 = no filter for that field.
  uint16_t filter_mcc = 0;  // --mcc <3-digit MCC>
  uint16_t filter_mnc = 0;  // --mnc <2 or 3-digit MNC>
};

class ArgManager {
public:
  static void defaultArgs(Args& args);
  static void usage(Args& args, const std::string& prog);
  static void parseArgs(Args& args, int argc, char **argv);
private:
  ArgManager() = delete;  // static only
};
