use pcap_crate::{Capture, Device};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn list_interfaces() -> Result<Vec<String>, String> {
    let devices = Device::list().map_err(|e| format!("Error listando interfaces: {}", e))?;
    Ok(devices.into_iter().map(|d| d.name).collect())
}

pub fn start_capture(
    interface_name: &str,
    stop_flag: Arc<AtomicBool>,
    mut callback: impl FnMut(&[u8], u32) + Send + 'static,
) -> Result<(), String> {
    let dev = Device::list()
        .map_err(|e| format!("Error: {}", e))?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interfaz {} no encontrada", interface_name))?;

    let mut cap = Capture::from_device(dev)
        .map_err(|e| format!("Error abriendo dispositivo: {}", e))?
        .promisc(true)
        .timeout(100)
        .open()
        .map_err(|e| format!("Error iniciando captura: {}", e))?;

    std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    callback(packet.data, packet.header.len);
                }
                Err(pcap_crate::Error::TimeoutExpired) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("Error en captura: {}", e);
                    break;
                }
            }
        }
    });

    Ok(())
}