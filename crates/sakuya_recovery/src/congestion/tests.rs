use super::InitialWindow;

#[test]
fn the_initial_window_follows_section_7_2() {
    let window = InitialWindow::RECOMMENDED;
    // min(12000, max(14720, 2400)).
    assert_eq!(window.bytes(1200), 12000);
    // min(14520, max(14720, 2904)).
    assert_eq!(window.bytes(1452), 14520);
    // min(90000, max(14720, 18000)).
    assert_eq!(window.bytes(9000), 18000);
}
