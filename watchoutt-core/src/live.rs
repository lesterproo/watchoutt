use pcap_crate::{Capture, Device};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn list_interfaces() -> Result<Vec<String>, String> {
    if let Ok(devices) = Device::list() {
        let names: Vec<String> = devices.into_iter().map(|d| d.name).collect();
        if !names.is_empty() {
            return Ok(names);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut names = Vec::new();
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    names.push(name);
                }
            }
            if !names.is_empty() {
                return Ok(names);
            }
        }
    }
    Err("No se encontraron interfaces de red".to_string())
}

pub fn start_capture_to_file(
    interface_name: &str,
    output_path: &std::path::Path,
    stop_flag: Arc<AtomicBool>,
) -> Result<(), String> {
    let dev = Device::list()
        .map_err(|e| format!("Error listando dispositivos: {}", e))?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interfaz {} no encontrada", interface_name))?;

    let mut cap = Capture::from_device(dev)
        .map_err(|e| format!("Error abriendo dispositivo: {}", e))?
        .promisc(true)
        .timeout(100)
        .open()
        .map_err(|e| format!("Error iniciando captura: {}", e))?;

    let mut savefile = cap
        .savefile(output_path)
        .map_err(|e| format!("Error creando archivo PCAP: {}", e))?;

    std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    let _ = savefile.write(&packet);
                }
                Err(pcap_crate::Error::TimeoutExpired) => continue,
                Err(e) => {
                    eprintln!("Error en captura: {}", e);
                    break;
                }
            }
        }
        // El archivo se cierra automáticamente aquí al terminar el hilo
    });

    Ok(())
}
