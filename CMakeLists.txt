set(PAL_NETWORK_SRCS "")
set(PAL_BLE_SRCS "")

if(CONFIG_PAL_NETWORK_ENABLED)
  set(PAL_NETWORK_SRCS "Esp32Network.cpp")
endif()

if(CONFIG_PAL_BLE_ENABLED)
  set(PAL_BLE_SRCS "Esp32Ble.cpp")
endif()

idf_component_register(
  SRCS "Esp32Platform.cpp" "Esp32Storage.cpp" "Esp32Crypto.cpp" ${PAL_BLE_SRCS} ${PAL_NETWORK_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES yahap
    PRIV_REQUIRES nvs_flash esp_event esp_timer mbedtls libsodium
)

# REQUIRES/PRIV_REQUIRES are collected by IDF's early-expansion pass, which runs
# before sdkconfig.cmake exists, so CONFIG_* conditionals inside the register
# call silently drop requirements. idf_component_optional_requires() runs only
# in the real pass and adds the dependency if the component is in the build.
if(CONFIG_PAL_BLE_ENABLED)
  idf_component_optional_requires(PUBLIC bt)
endif()

if(CONFIG_PAL_NETWORK_ENABLED)
  idf_component_optional_requires(PUBLIC mdns)
  idf_component_optional_requires(PRIVATE esp_wifi)
endif()
