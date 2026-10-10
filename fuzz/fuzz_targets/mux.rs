#![no_main]

use libfuzzer_sys::fuzz_target;
use syncwire::{
    Chunk, ChunkRequest, Direction, Extent, Header, Ping, Want, WhoAmI,
};

fuzz_target!(|data: &[u8]| {
    for direction in [Direction::Request, Direction::Response] {
        if let Some(bytes) = data.first_chunk::<9>() {
            if let Ok(header) = Header::decode(bytes, direction) {
                assert_eq!(header.encode(), *bytes);
            }
        }
    }
    if let Ok(x) = Want::try_from(data) {
        assert_eq!(x.encode(), data);
    }
    if let Ok(x) = Extent::try_from(data) {
        assert_eq!(x.encode(), data);
    }
    if let Ok(x) = ChunkRequest::try_from(data) {
        assert_eq!(x.encode(), data);
    }
    if let Ok(x) = Ping::try_from(data) {
        assert_eq!(x.encode(), data);
    }
    if let Ok(x) = WhoAmI::try_from(data) {
        assert_eq!(x.encode(), data);
    }
    if let Ok(x) = Chunk::decode_snapshot(data) {
        assert_eq!(x.encode().ok().as_deref(), Some(data));
    }
    if let Ok(x) = Chunk::decode_log(data) {
        assert_eq!(x.encode().ok().as_deref(), Some(data));
    }
});
