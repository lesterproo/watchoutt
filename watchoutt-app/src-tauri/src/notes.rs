use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct Note {
    pub id: u64,
    pub target_type: String,
    pub target_id: u64,
    pub text: String,
    pub created_at_ns: i64,
}

pub fn load_notes(dir: &Path) -> Result<Vec<Note>, String> {
    let path = dir.join("notes.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).map_err(|e| format!("Error leyendo notas: {e}"))?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&content).map_err(|e| format!("Error parseando notas: {e}"))
}

pub fn save_notes(dir: &Path, notes: &[Note]) -> Result<(), String> {
    let path = dir.join("notes.json");
    let json =
        serde_json::to_string_pretty(notes).map_err(|e| format!("Error serializando: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("Error escribiendo notas: {e}"))
}

pub fn next_id(notes: &[Note]) -> u64 {
    notes.iter().map(|n| n.id).max().unwrap_or(0) + 1
}
