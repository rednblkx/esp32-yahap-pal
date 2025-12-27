idf_component_register(
    SRCS  "Esp32Platform.cpp" "Esp32Storage.cpp" "Esp32Crypto.cpp" "Esp32Ble.cpp" "Esp32Network.cpp"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES hap_wrapper bt libsodium nvs_flash esp_wifi mdns esp_event mbedtls esp_timer
)
