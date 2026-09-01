#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = link_p2p::tun_ctl::decode_request_frame(data);
    let _ = link_p2p::tun_ctl::decode_response_frame(data);

    // Truncated / header-only prefixes.
    if !data.is_empty() {
        let _ = link_p2p::tun_ctl::decode_request_frame(&data[..1]);
        let _ = link_p2p::tun_ctl::decode_response_frame(&data[..1]);
    }
    if data.len() >= 8 {
        let _ = link_p2p::tun_ctl::decode_request_frame(&data[..8]);
        let _ = link_p2p::tun_ctl::decode_response_frame(&data[..8]);
    }
    if data.len() >= 9 {
        let _ = link_p2p::tun_ctl::decode_request_frame(&data[..9]);
        let _ = link_p2p::tun_ctl::decode_response_frame(&data[..9]);
    }
});
