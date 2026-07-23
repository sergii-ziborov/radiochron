#[test]
fn apple_channel_frequency_mapping_covers_all_wifi_bands() {
    assert_eq!(super::channel_frequency_khz(1, 1), 2_412_000);
    assert_eq!(super::channel_frequency_khz(36, 2), 5_180_000);
    assert_eq!(super::channel_frequency_khz(5, 3), 5_975_000);
}
