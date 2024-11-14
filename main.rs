// *************************************************
// ---- working with fuzzy and human hashes -----
// *************************************************
use actix_files as afs;
use actix_multipart::Multipart;
use actix_web::{web, App, Error, HttpResponse, HttpServer, Responder};
use futures_util::stream::StreamExt as _;
use ring::digest::{Context, SHA256};
use serde::Serialize;
use std::fs::{File, create_dir_all};
use std::io::{self, Read, Write};
use std::path::Path;
use md5;
use hex;
use infer;
use sanitize_filename::sanitize;
use human_hash::humanize; 
use uuid::Uuid;
use ssdeep::hash_file;
use std::process::Command;
use sha1::Digest; // Import Digest trait from sha1
use pesign::PeSign; // Import PeSign from pesign

#[derive(Serialize)]
struct FileInfo {
    filesize: String,
    filetype_infer: String, // File type from infer
    filetype_command: String, // File type from the file command
    // filetype: String,
    md5: String,
    sha256: String,
    sha1: String,
    sha384: String,
    humanhash: String,
    fuzzy_hash: String,
    capa_command: String,
}

async fn save_file(mut payload: Multipart) -> Result<HttpResponse, Error> {
    let mut file_info = None;

    while let Some(Ok(mut field)) = payload.next().await {
        let content_disposition = field.content_disposition().unwrap();
        let filename = content_disposition.get_filename().unwrap();
        let filepath = format!("./uploads/{}", sanitize(filename));
        let filepath_clone = filepath.clone();

        let mut f = web::block(move || File::create(filepath)).await??;

        while let Some(chunk) = field.next().await {
            let data = chunk?;
            f = web::block(move || {
                f.write_all(&data)?;
                Ok::<_, io::Error>(f)
            })
            .await??;
        }

        file_info = Some(analyze_file(filepath_clone));
    }

    Ok(HttpResponse::Ok().json(file_info.unwrap()))
}

fn analyze_file(filepath: String) -> FileInfo {
    let metadata = std::fs::metadata(&filepath).unwrap();
    let filesize = format_size(metadata.len());

    let mut file = File::open(&filepath).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    // let filetype = infer::get(&buffer).map_or("unknown".to_string(), |kind| kind.mime_type().to_string());
    // Get file type using infer
    let mut filetype_infer = infer::get(&buffer).map_or("unknown".to_string(), |kind| kind.mime_type().to_string());

    // Call the `file` command to get file type
    let file_command_output = Command::new("file")
        .arg(&filepath)
        .output()
        .expect("Failed to execute command");

    let filetype_command = String::from_utf8_lossy(&file_command_output.stdout).to_string();

    // Extract the part after the filename
    let filetype_command = filetype_command
        .split(':') // Split on colon
        .nth(1) // Get the second part (after the colon)
        .unwrap_or("") // Default to an empty string if not found
        .trim(); // Trim whitespace

    let md5 = md5::compute(&buffer);
    let sha256 = sha256_digest(&buffer);
    let sha1 = sha1::Sha1::digest(&buffer);
    let sha384 = sha2::Sha384::digest(&buffer);

    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, &buffer); 
    let humanhash = humanize(&uuid, 4);

    let fuzzy_hash = hash_file(&filepath); 
    let fuzzy_hash_str = match fuzzy_hash { Ok(fh) => fh.to_string(), Err(_) => String::from("N/A"), }; 

    let mut capa_command = String::new();

    // Check if the file is a PE file and use pesign
    if filetype_infer == "application/vnd.microsoft.portable-executable" {
        if let Some(_pesign) = PeSign::from_pe_path(&filepath).unwrap() {
            println!("The file '{}' is a signed PE!", filepath);
            // Append a suffix to filetype_infer
            filetype_infer = format!("{} (SIGNED PE FILE)", filetype_infer);
        } else {
            println!("The file '{}' is not a signed PE file!", filepath);
            // Append a suffix to filetype_infer
            filetype_infer = format!("{} (NOT SIGNED PE FILE!!!)", filetype_infer);
        }
        
        // Execute the capa command only for PE files
        let capa_command_output = Command::new("./capa")
        .arg(&filepath)
        // .arg("> capa_temp.txt")
        .output()
        .expect("Failed to execute command");

        // Capture the output of the command
        capa_command = String::from_utf8_lossy(&capa_command_output.stdout).to_string();

        // Print stderr for debugging
        // let stderr = String::from_utf8_lossy(&capa_command_output.stderr);
        // if !stderr.is_empty() {
        //     println!("Error output from capa command: {}", stderr);
        // }
    }

    FileInfo {
        filesize,
        filetype_infer, // Use the output from infer
        filetype_command: filetype_command.trim().to_string(), // Use the output from the file command
        md5: format!("{:x}", md5),
        sha256,
        sha1: format!("{:x}", sha1),
        sha384: format!("{:x}", sha384),
        humanhash, 
        fuzzy_hash: fuzzy_hash_str,
        capa_command,
    }
}

fn format_size(bytes: u64) -> String {
    let sizes = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut i = 0;
    while size >= 1024.0 && i < sizes.len() - 1 {
        size /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", size, sizes[i])
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    let digest = context.finish();
    hex::encode(digest.as_ref())
}

async fn index() -> impl Responder {
    afs::NamedFile::open_async("./index.html").await.unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Ensure the upload directory exists
    if !Path::new("./uploads").exists() {
        create_dir_all("./uploads").expect("Failed to create upload directory");
    }

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/upload", web::post().to(save_file))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
