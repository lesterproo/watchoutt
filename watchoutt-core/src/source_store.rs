use std::fs::{self, File, OpenOptions};
use std::io::{self, copy};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{DomainError, Investigation, SourceFile, SourceFormat, SourceId};

#[derive(Debug)]
pub enum SourceImportError {
    Io(io::Error),
    Domain(DomainError),
    NotRegularFile(PathBuf),
    HashToolUnavailable,
    HashFailed(String),
    InvalidHashOutput,
}

impl std::fmt::Display for SourceImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Error de archivos: {error}"),
            Self::Domain(error) => write!(f, "Error de investigación: {error}"),
            Self::NotRegularFile(path) => {
                write!(f, "No es un archivo normal: {}", path.display())
            }
            Self::HashToolUnavailable => {
                write!(f, "No se encontró sha256sum en el sistema")
            }
            Self::HashFailed(message) => {
                write!(f, "No se pudo calcular SHA-256: {message}")
            }
            Self::InvalidHashOutput => {
                write!(f, "sha256sum devolvió un resultado no válido")
            }
        }
    }
}

impl std::error::Error for SourceImportError {}

impl From<io::Error> for SourceImportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DomainError> for SourceImportError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

/// Importa una copia del archivo a la investigación.
/// El archivo original permanece intacto.
pub fn import_source(
    investigation: &mut Investigation,
    source_id: SourceId,
    original_path: &Path,
    investigation_dir: &Path,
    imported_at_unix_ns: i64,
) -> Result<SourceFile, SourceImportError> {
    // No permitir IDs repetidos dentro de la investigación.
    if investigation
        .sources()
        .iter()
        .any(|source| source.id == source_id)
    {
        return Err(SourceImportError::Domain(DomainError::DuplicateId {
            entity: "fuentes",
            id: source_id.0,
        }));
    }

    let original_name = original_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            SourceImportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "La ruta no contiene un nombre de archivo válido",
            ))
        })?;

    let mut input = File::open(original_path)?;
    let metadata = input.metadata()?;

    if !metadata.is_file() {
        return Err(SourceImportError::NotRegularFile(
            original_path.to_path_buf(),
        ));
    }

    // Todas las fuentes originales se guardan en esta subcarpeta.
    let sources_dir = investigation_dir.join("sources");
    fs::create_dir_all(&sources_dir)?;

    // El ID diferencia archivos con el mismo nombre.
    let stored_name = format!("{}_{}", source_id.0, original_name);
    let destination = sources_dir.join(&stored_name);

    // create_new impide sobrescribir una fuente que ya exista.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)?;

    // Copia por bloques, sin cargar el archivo completo en RAM.
    if let Err(error) = copy(&mut input, &mut output) {
        drop(output);
        let _ = fs::remove_file(&destination);
        return Err(SourceImportError::Io(error));
    }

    if let Err(error) = output.sync_all() {
        drop(output);
        let _ = fs::remove_file(&destination);
        return Err(SourceImportError::Io(error));
    }

    drop(output);

    // Calculamos el hash de la copia que realmente conservaremos.
    let sha256 = match calculate_sha256(&destination) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = fs::remove_file(&destination);
            return Err(error);
        }
    };

    let size_bytes = match fs::metadata(&destination) {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            let _ = fs::remove_file(&destination);
            return Err(SourceImportError::Io(error));
        }
    };

    let source = SourceFile {
        id: source_id,
        file_name: original_name.to_string(),
        relative_path: PathBuf::from("sources").join(&stored_name),
        format: detect_format(original_path),
        size_bytes,
        sha256: Some(sha256),
        imported_at_unix_ns,
    };

    // Registrar la fuente en la investigación.
    if let Err(error) = investigation.add_source(source.clone()) {
        let _ = fs::remove_file(&destination);
        return Err(SourceImportError::Domain(error));
    }

    Ok(source)
}

/// Utiliza la herramienta sha256sum del sistema.
/// Lee el archivo de forma progresiva, sin cargarlo entero en memoria.
fn calculate_sha256(path: &Path) -> Result<String, SourceImportError> {
    let output = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                SourceImportError::HashToolUnavailable
            } else {
                SourceImportError::Io(error)
            }
        })?;

    if !output.status.success() {
        return Err(SourceImportError::HashFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let hash = stdout
        .split_whitespace()
        .next()
        .ok_or(SourceImportError::InvalidHashOutput)?;

    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SourceImportError::InvalidHashOutput);
    }

    Ok(hash.to_ascii_lowercase())
}

/// Clasificación preliminar basada en la extensión.
/// Más adelante el analizador verificará el contenido real del archivo.
fn detect_format(path: &Path) -> SourceFormat {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("pcap") => SourceFormat::Pcap,
        Some(ext) if ext.eq_ignore_ascii_case("pcapng") => SourceFormat::PcapNg,
        Some(ext) if ext.eq_ignore_ascii_case("csv") => SourceFormat::Csv,
        Some(ext) if ext.eq_ignore_ascii_case("json") => SourceFormat::Json,
        Some(ext) if ext.eq_ignore_ascii_case("txt") => SourceFormat::Text,
        _ => SourceFormat::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvestigationId;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path =
            std::env::temp_dir().join(format!("nextrace-{label}-{}-{nonce}", std::process::id()));

        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn imports_copy_and_hash_without_removing_original() {
        let temp = temporary_directory("import");
        let original = temp.join("capture.pcap");
        let investigation_dir = temp.join("investigation");

        let contents = b"NEXTRACE test capture\n";
        fs::write(&original, contents).unwrap();

        let mut investigation = Investigation::new(InvestigationId(1), "Test", None, 0).unwrap();

        let source = import_source(
            &mut investigation,
            SourceId(1),
            &original,
            &investigation_dir,
            10,
        )
        .unwrap();

        let stored = investigation_dir.join(&source.relative_path);

        // El original permanece y la copia contiene los mismos bytes.
        assert!(original.exists());
        assert_eq!(fs::read(&stored).unwrap(), contents);

        assert_eq!(source.size_bytes, contents.len() as u64);
        assert_eq!(source.format, SourceFormat::Pcap);

        // SHA-256 conocido del contenido de prueba.
        assert_eq!(
            source.sha256.as_deref(),
            Some("02e047997b2836cc0d4ceed4a84c3cef83744d9646877648c0e22693c83b7e23")
        );

        assert_eq!(investigation.sources().len(), 1);

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_an_existing_stored_file() {
        let temp = temporary_directory("collision");
        let original = temp.join("capture.txt");
        let investigation_dir = temp.join("investigation");

        fs::write(&original, b"test").unwrap();

        let sources_dir = investigation_dir.join("sources");
        fs::create_dir_all(&sources_dir).unwrap();

        let existing = sources_dir.join("7_capture.txt");
        fs::write(&existing, b"existing").unwrap();

        let mut investigation = Investigation::new(InvestigationId(1), "Test", None, 0).unwrap();

        let result = import_source(
            &mut investigation,
            SourceId(7),
            &original,
            &investigation_dir,
            10,
        );

        assert!(result.is_err());

        // El archivo previo no debe haber sido modificado.
        assert_eq!(fs::read(&existing).unwrap(), b"existing");
        assert!(investigation.sources().is_empty());

        fs::remove_dir_all(temp).unwrap();
    }
}
