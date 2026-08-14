#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <vector>
#include "esphome/core/component.h"
#include "esphome/core/gpio.h"
#include "esphome/components/spi/spi.h"
#include "../bambuddy_api/bambuddy_api.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace esphome {
namespace bambuddy_nfc {

static const char *const NFC_TAG = "bambuddy_nfc";

// PN532 SPI command bytes
static constexpr uint8_t PN532_SPI_DATAWRITE = 0x01;
static constexpr uint8_t PN532_SPI_STATREAD  = 0x02;
static constexpr uint8_t PN532_SPI_DATAREAD  = 0x03;

// PN532 firmware status byte returned before data frames
static constexpr uint8_t PN532_PREAMBLE   = 0x00;
static constexpr uint8_t PN532_STARTCODE1 = 0x00;
static constexpr uint8_t PN532_STARTCODE2 = 0xFF;
static constexpr uint8_t PN532_POSTAMBLE  = 0x00;
static constexpr uint8_t PN532_TFI_HOST   = 0xD4;  // Host → PN532
static constexpr uint8_t PN532_TFI_PN532  = 0xD5;  // PN532 → Host
static constexpr uint8_t PN532_READY  = 0x01;

// PN532 commands used
static constexpr uint8_t PN532_CMD_SAMCONFIGURATION  = 0x14;
static constexpr uint8_t PN532_CMD_INLISTPASSIVETARGET = 0x4A;
static constexpr uint8_t PN532_CMD_INDATAEXCHANGE    = 0x40;
static constexpr uint8_t PN532_CMD_GETFIRMWAREVERSION = 0x02;

// MIFARE commands
static constexpr uint8_t MFC_AUTH_KEY_A  = 0x60;
static constexpr uint8_t MFC_READ        = 0x30;

// NTAG commands
static constexpr uint8_t NTAG_WRITE = 0xA2;

// Bambu MIFARE Classic HKDF key derivation constants
// (ported from pico-nfc-bridge.ino / spoolbuddy pn5180.py)
static const uint8_t BAMBU_MASTER_KEY[16] = {
    0x9A, 0x75, 0x9C, 0xF2, 0xC4, 0xF7, 0xCA, 0xFF,
    0x22, 0x2C, 0xB9, 0x76, 0x9B, 0x41, 0xBC, 0x96,
};
// "RFID-A\0" — 7 bytes including null terminator
static const uint8_t BAMBU_CONTEXT[7] = {
    'R', 'F', 'I', 'D', '-', 'A', 0x00
};
// Bambu blocks to read for material info.
//   1 = Tray Info Index (material variant id + material id)
//   2 = Filament Type ("PLA")
//   4 = Detailed Filament Type ("PLA Basic")
//   5 = RGBA colour + spool weight + filament diameter
static const uint8_t BAMBU_BLOCKS[] = {1, 2, 4, 5};

// Block 9 holds the 16-byte Tray UID — the value Bambu printers report as
// tray_uuid and the only field on the tag that uniquely identifies a spool.
// Read separately from BAMBU_BLOCKS because it lives in sector 2: a tag that
// refuses that sector must still yield the material info above rather than
// failing the whole read.
static constexpr uint8_t BAMBU_TRAY_UID_BLOCK = 9;

enum class NFCState {
  IDLE,
  TAG_PRESENT,
};

/**
 * BambuddyNFCComponent
 *
 * Drives a PN532 NFC reader via SPI and implements:
 *   - ISO 14443A tag activation (MIFARE Classic + NTAG)
 *   - HKDF-SHA256 key derivation for Bambu Lab MIFARE Classic tags
 *   - Tag-presence state machine (detect, present, removed)
 *   - NTAG write support (triggered by pending_write in BambuddyAPIComponent)
 *   - Callbacks to BambuddyAPIComponent on scan/remove events
 */
class BambuddyNFCComponent
    : public Component,
      public spi::SPIDevice<spi::BIT_ORDER_LSB_FIRST, spi::CLOCK_POLARITY_LOW,
                            spi::CLOCK_PHASE_LEADING, spi::DATA_RATE_1MHZ> {
 public:
  void setup() override;
  void loop() override;
  float get_setup_priority() const override {
    return setup_priority::DATA;
  }

  void set_api_component(bambuddy_api::BambuddyAPIComponent *api) {
    api_ = api;
  }
  void set_poll_interval(uint32_t ms) { poll_interval_ms_ = ms; }
  void set_miss_threshold(uint8_t n) { miss_threshold_ = n; }
  // Optional IRQ pin (PN532 open-drain, active-LOW).
  // When set, pn532_wait_ready() watches this GPIO instead of polling the SPI
  // status register — eliminates ~100 SPI transactions per no-tag cycle.
  void set_irq_pin(GPIOPin *pin) { irq_pin_ = pin; }
  // Low-power mode: widen the detect cadence while the console sleeps (called by
  // the UI sleep state machine). The RF field is energized for most of each
  // detect cycle, so a longer inter-cycle gap markedly cuts RF power and lets
  // core 1 idle more — at the cost of higher tag-detect (wake) latency.
  void set_low_power(bool v) { low_power_ = v; }
  // Enable/disable tag scanning entirely. When false the poll task leaves the
  // RF field off and idles — used for "NFC in sleep: Off" (max power saving, no
  // local-reader wake). Re-enabled on wake.
  void set_scan_enabled(bool v) { scan_enabled_ = v; }
  // True once pn532_init() has succeeded and the reader is answering.
  //
  // Read this, not DisplayState::nfc_ok — bambuddy_api sets that field to true
  // on every successful heartbeat (and hard-codes "nfc_ok":true in the payload
  // it sends), so it reports backend connectivity, not reader health. A dead
  // PN532 shows up there as healthy within 10 s of dying.
  bool nfc_ok() const { return nfc_ok_; }

 protected:
  // ---- Background polling task ----
  // The PN532 SPI handshake busy-waits up to ~500 ms per poll when no tag is
  // present.  Running it on its own task keeps that latency off the main loop
  // so LVGL / touch stay responsive.
  static void poll_task_trampoline(void *arg);
  void poll_task_loop();
  void poll_once();  // one detect/handle cycle

  TaskHandle_t poll_task_handle_{nullptr};

  // ---- PN532 SPI low-level ----
  bool pn532_spi_read_status(uint8_t &status);
  bool pn532_spi_read_data(uint8_t *data, size_t len);
  bool pn532_wait_ready(uint32_t timeout_ms = 100);
  // Wait for the PN532 to release IRQ (drive it back HIGH) after we have read a
  // frame. Bounded and advisory: returns false on timeout but callers continue,
  // so this can only ever cost latency, never functionality.
  bool pn532_wait_irq_released(uint32_t timeout_ms = 20);
  bool pn532_write_command(const std::vector<uint8_t> &cmd);
  // Send a host ACK frame. UM10232 §7.1.1.1: this is the *only* way for the
  // host to cancel a command the PN532 is still executing. Needed because
  // InListPassiveTarget has no timeout and otherwise runs until a tag appears.
  void pn532_send_ack();
  bool pn532_read_response(std::vector<uint8_t> &resp, uint32_t timeout_ms = 100);
  bool pn532_send_receive(const std::vector<uint8_t> &cmd,
                          std::vector<uint8_t> &resp,
                          uint32_t timeout_ms = 200);

  // ---- Liveness ----
  // A tagless InListPassiveTarget legitimately times out every poll, so detect
  // failures say nothing about the link. GetFirmwareVersion does: it must
  // answer immediately. Run it periodically and use *its* failures to decide
  // the reader has gone deaf, so "no tag" and "no reader" stop being the same
  // observation.
  bool pn532_probe_alive();
  uint32_t last_probe_ms_{0};
  uint8_t probe_fail_streak_{0};
  static constexpr uint32_t PROBE_INTERVAL_MS = 30000;
  static constexpr uint8_t PROBE_FAILS_BEFORE_REINIT = 3;

  // ---- PN532 high-level ----
  bool pn532_init();
  // Detect a single ISO 14443A tag; fills uid + sak on success
  bool pn532_detect_tag(std::vector<uint8_t> &uid, uint8_t &sak);

  // ---- MIFARE Classic ----
  bool mfc_authenticate(uint8_t target_num, uint8_t block,
                         const uint8_t *key6, const uint8_t *uid4);
  bool mfc_read_block(uint8_t target_num, uint8_t block,
                      uint8_t data_out[16]);
  // Read Bambu blocks 1,2,4,5 using HKDF-derived keys
  bool read_bambu_blocks(uint8_t target_num,
                          const std::vector<uint8_t> &uid,
                          std::vector<std::pair<uint8_t, std::array<uint8_t, 16>>> &blocks_out);

  // ---- NTAG ----
  bool ntag_write_page(uint8_t target_num, uint8_t page,
                       const uint8_t data[4]);
  // Read 4 pages (16 bytes) from an activated NTAG starting at start_page.
  // Uses the same 0x30 READ command as Mifare Classic block reads.
  bool ntag_read_pages(uint8_t target_num, uint8_t start_page, uint8_t out[16]);
  // Read and parse the first NDEF record in the NTAG data area (pages 4+).
  // Returns "open_tag_3d" if the record type contains "opentag",
  // "ndef" for any other valid NDEF, or "" if the tag is unreadable/blank.
  std::string ntag_detect_ndef_format(uint8_t target_num);
  // If the API has a pending NDEF write and the activated tag is an NTAG,
  // perform it.  Returns true if a write was attempted (success or failure),
  // false if there was nothing to do.  Fully logged for diagnosis.
  bool attempt_pending_write(const std::vector<uint8_t> &uid, uint8_t sak);

  // ---- HKDF-SHA256 ----
  // Derive 96 bytes of key material from UID using Bambu master key
  void hkdf_derive_keys(const uint8_t *uid, size_t uid_len,
                         uint8_t okm[96]);
  // Compute HMAC-SHA256
  void hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[32]);

  // ---- UUID extraction ----
  static std::string extract_tray_uuid(
      const std::vector<std::pair<uint8_t, std::array<uint8_t, 16>>> &blocks);

  // ---- State ----
  GPIOPin *irq_pin_{nullptr};
  bambuddy_api::BambuddyAPIComponent *api_{nullptr};
  NFCState state_{NFCState::IDLE};
  std::vector<uint8_t> current_uid_;
  uint8_t current_sak_{0};
  uint8_t miss_count_{0};
  uint8_t miss_threshold_{3};
  uint32_t poll_interval_ms_{300};
  std::atomic<bool> low_power_{false};  // true while the console sleeps → slow polling
  std::atomic<bool> scan_enabled_{true};  // false → skip detection entirely (RF off)
  bool nfc_ok_{false};
};

}  // namespace bambuddy_nfc
}  // namespace esphome
