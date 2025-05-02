use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct WidgetInfo {
    pub nid: u8,
    pub node_count: u32,
    pub widget_type: u32,
    pub conn_list: Vec<u8>,
    pub config_default: u32,
    pub pin_caps: u32,
    pub amp_in_caps: u32,
    pub amp_out_caps: u32,
    pub volume_knob: u32,
}

impl WidgetInfo {
    pub fn new(nid: u8) -> Self {
        WidgetInfo {
            nid,
            node_count: 0,
            widget_type: 0,
            conn_list: Vec::new(),
            config_default: 0,
            pin_caps: 0,
            amp_in_caps: 0,
            amp_out_caps: 0,
            volume_knob: 0,
        }
    }
}
