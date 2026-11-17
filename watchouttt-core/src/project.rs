
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::persistence::{
    load_investigation, save_investigation, PersistenceError,
};
use crate::Investigation;

pub const PROJECT_FILE_NAME: &str = "investigation.nxt";

#[cfg(test)]
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectValidationReport {
    /// Fuentes cuyo tamaño y SHA-256 fueron comprobados.
    pub sources_verified: usize,

    /// Fuentes existentes y con tamaño correcto, pero sin hash registrado.
    pub sources_without_hash: usize,
}

#[derive(Debug)]
pub enum ProjectError {
    Io(io::Error),
    Persistence(PersistenceError),
    UnsafeSourcePath(PathBuf),
    MissingSource(PathBuf),
    NotRegularFile(PathBuf),
    SizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    HashToolUnavailable,
    HashFailed(String),
    InvalidHashOutput,
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Error de archivos del proyecto: {error}"),
            Self::Persistence(error) => {
                write!(f, "Error al leer o guardar la investigación: {error}")
            }
            Self::UnsafeSourcePath(path) => write!(
                f,
                "La ruta de una fuente no es segura o sale del proyecto: {}",
                path.display()
            ),
            Self::MissingSource(path) => {
                write!(f, "No se encuentra una fuente del proyecto: {}", path.display())
            }
            Self::NotRegularFile(path) => {
                write!(f, "Una fuente no es un archivo normal: {}", path.display())
            }
            Self::SizeMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "El tamaño de la fuente {} no coincide: esperado {expected} bytes, encontrado {actual} bytes",
                path.display()
            ),
            Self::HashToolUnavailable => {
                write!(f, "No se encontró la herramienta sha256sum")
            }
            Self::HashFailed(message) => {
                write!(f, "No se pudo calcular SHA-256: {message}")
            }
            Self::InvalidHashOutput => {
                write!(f, "sha256sum devolvió un resultado no válido")
            }
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "La integridad de la fuente {} no coincide. Esperado: {expected}; obtenido: {actual}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ProjectError {}

impl From<io::Error> for ProjectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PersistenceError> for ProjectError {
    fn from(error: PersistenceError) -> Self {
        Self::Persistence(error)
    }
}

/// Guarda una investigación dentro de una carpeta de proyecto.
///
/// La carpeta debe ser la misma que se utilizó como raíz al importar
/// las fuentes mediante import_source().
///
/// Las fuentes no se vuelven a copiar: se valida su ubicación e
/// integridad y después se guarda investigation.nxt.
pub fn save_project(
    investigation: &Investigation,
    project_dir: impl AsRef<Path>,
) -> Result<ProjectValidationReport, ProjectError> {
    let project_dir = project_dir.as_ref();

    fs::create_dir_all(project_dir)?;

    let report = validate_project_sources(investigation, project_dir)?;

    let destination = project_dir.join(PROJECT_FILE_NAME);
    save_investigation(investigation, destination)?;

    Ok(report)
}

/// Abre un proyecto y comprueba la integridad de todas sus fuentes.
///
/// Si falta una fuente, su tamaño cambió, su hash no coincide o su
/// ruta intenta salir de la carpeta del proyecto, la operación falla.
pub fn open_project(
    project_dir: impl AsRef<Path>,
) -> Result<(Investigation, ProjectValidationReport), ProjectError> {
    let project_dir = project_dir.as_ref();
    let project_file = project_dir.join(PROJECT_FILE_NAME);

    let investigation = load_investigation(project_file)?;
    let report = validate_project_sources(&investigation, project_dir)?;

    Ok((investigation, report))
}

/// Comprueba que todas las fuentes de una investigación estén
/// dentro de la carpeta del proyecto y mantengan su integridad.
pub fn validate_project_sources(
    investigation: &Investigation,
    project_dir: impl AsRef<Path>,
) -> Result<ProjectValidationReport, ProjectError> {
    let root = fs::canonicalize(project_dir)?;

    let mut report = ProjectValidationReport::default();

    for source in investigation.sources() {
        let relative_path = &source.relative_path;

        // Solo se permiten componentes normales de una ruta relativa.
        // Esto rechaza rutas absolutas, "..", "." y prefijos de unidades.
        let safe_relative = !relative_path.as_os_str().is_empty()
            && relative_path
                .components()
                .all(|component| matches!(component, Component::Normal(_)));

        if !safe_relative {
            return Err(ProjectError::UnsafeSourcePath(
                relative_path.to_path_buf(),
            ));
        }

        let candidate = root.join(relative_path);

        // canonicalize resuelve también los enlaces simbólicos.
        // Así se impide que una fuente apunte fuera de la carpeta.
        let canonical_source = match fs::canonicalize(&candidate) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ProjectError::MissingSource(candidate));
            }
            Err(error) => return Err(ProjectError::Io(error)),
        };

        if !canonical_source.starts_with(&root) {
            return Err(ProjectError::UnsafeSourcePath(
                relative_path.to_path_buf(),
            ));
        }

        let metadata = fs::metadata(&canonical_source)?;

        if !metadata.is_file() {
            return Err(ProjectError::NotRegularFile(
                relative_path.to_path_buf(),
            ));
        }

        if metadata.len() != source.size_bytes {
            return Err(ProjectError::SizeMismatch {
                path: relative_path.to_path_buf(),
                expected: source.size_bytes,
                actual: metadata.len(),
            });
        }

        match &source.sha256 {
            Some(expected_hash) => {
                let actual_hash = calculate_sha256(&canonical_source)?;

                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    return Err(ProjectError::HashMismatch {
                        path: relative_path.to_path_buf(),
                        expected: expected_hash.clone(),
                        actual: actual_hash,
                    });
                }

                report.sources_verified += 1;
            }
            None => {
                report.sources_without_hash += 1;
            }
        }
    }

    Ok(report)
}

fn calculate_sha256(path: &Path) -> Result<String, ProjectError> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                ProjectError::HashToolUnavailable
            } else {
                ProjectError::Io(error)
            }
        })?;

    if !output.status.success() {
        return Err(ProjectError::HashFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash = stdout
        .split_whitespace()
        .next()
        .ok_or(ProjectError::InvalidHashOutput)?;

    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProjectError::InvalidHashOutput);
    }

    Ok(hash.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InvestigationId, SourceFile, SourceFormat, SourceId};

    fn temporary_directory(label: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nextrace_project_test_{label}_{}_{}",
            std::process::id(),
            id
        ));

        fs::create_dir_all(&path).unwrap();
        path
    }

    fn create_investigation(
        relative_path: &str,
        size_bytes: u64,
        sha256: Option<String>,
    ) -> Investigation {
        let mut investigation = Investigation::new(
            InvestigationId(1),
            "Proyecto de prueba",
            Some("Prueba del almacenamiento de proyectos".to_string()),
            1_798_000_000_000_000_000,
        )
        .unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "capture.pcap".to_string(),
                relative_path: PathBuf::from(relative_path),
                format: SourceFormat::Pcap,
                size_bytes,
                sha256,
                imported_at_unix_ns: 1_798_000_000_000_000_000,
            })
            .unwrap();

        investigation
    }

    fn sha256_of(path: &Path) -> String {
        calculate_sha256(path).unwrap()
    }

    #[test]
    fn saves_and_opens_project_with_valid_source() {
        let root = temporary_directory("valid");
        let sources_dir = root.join("sources");
        fs::create_dir_all(&sources_dir).unwrap();

        let source_path = sources_dir.join("1_capture.pcap");
        fs::write(&source_path, b"pcap-test-data").unwrap();

        let investigation = create_investigation(
            "sources/1_capture.pcap",
            fs::metadata(&source_path).unwrap().len(),
            Some(sha256_of(&source_path)),
        );

        let save_report = save_project(&investigation, &root).unwrap();

        assert_eq!(save_report.sources_verified, 1);
        assert_eq!(save_report.sources_without_hash, 0);
        assert!(root.join(PROJECT_FILE_NAME).is_file());

        let (restored, open_report) = open_project(&root).unwrap();

        assert_eq!(restored, investigation);
        assert_eq!(open_report.sources_verified, 1);
        assert_eq!(open_report.sources_without_hash, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_source_with_modified_content() {
        let root = temporary_directory("modified");
        let sources_dir = root.join("sources");
        fs::create_dir_all(&sources_dir).unwrap();

        let source_path = sources_dir.join("1_capture.pcap");
        fs::write(&source_path, b"original-data").unwrap();

        let investigation = create_investigation(
            "sources/1_capture.pcap",
            fs::metadata(&source_path).unwrap().len(),
            Some(sha256_of(&source_path)),
        );

        // Mismo tamaño, distinto contenido: debe detectarse por SHA-256.
        fs::write(&source_path, b"modified-data").unwrap();

        let result = save_project(&investigation, &root);

        assert!(matches!(result, Err(ProjectError::HashMismatch { .. })));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_source() {
        let root = temporary_directory("missing");

        let investigation = create_investigation(
            "sources/1_capture.pcap",
            10,
            None,
        );

        let result = validate_project_sources(&investigation, &root);

        assert!(matches!(result, Err(ProjectError::MissingSource(_))));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let root = temporary_directory("traversal");

        let investigation = create_investigation(
            "../outside.pcap",
            10,
            None,
        );

        let result = validate_project_sources(&investigation, &root);

        assert!(matches!(result, Err(ProjectError::UnsafeSourcePath(_))));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn counts_sources_without_hash() {
        let root = temporary_directory("no_hash");
        let sources_dir = root.join("sources");
        fs::create_dir_all(&sources_dir).unwrap();

        let source_path = sources_dir.join("1_capture.pcap");
        fs::write(&source_path, b"data-without-hash").unwrap();

        let investigation = create_investigation(
            "sources/1_capture.pcap",
            fs::metadata(&source_path).unwrap().len(),
            None,
        );

        let report = validate_project_sources(&investigation, &root).unwrap();

        assert_eq!(report.sources_verified, 0);
        assert_eq!(report.sources_without_hash, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_that_escapes_project_directory() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("symlink");
        let outside = temporary_directory("outside");

        let sources_dir = root.join("sources");
        fs::create_dir_all(&sources_dir).unwrap();

        let outside_file = outside.join("outside.pcap");
        fs::write(&outside_file, b"outside-data").unwrap();

        let link_path = sources_dir.join("1_capture.pcap");
        symlink(&outside_file, &link_path).unwrap();

        let investigation = create_investigation(
            "sources/1_capture.pcap",
            fs::metadata(&outside_file).unwrap().len(),
            None,
        );

        let result = validate_project_sources(&investigation, &root);

        assert!(matches!(result, Err(ProjectError::UnsafeSourcePath(_))));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
