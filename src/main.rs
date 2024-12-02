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
use std::fs;

#[derive(Serialize)]
struct FileInfo {
    filesize: String,
    filetype_infer: String, // File type from infer
    filetype_command: String, // File type from the file command
    filetype_trid: String,
    md5: String,
    sha256: String,
    sha1: String,
    sha384: String,
    humanhash: String,
    fuzzy_hash: String,
    exiftool_command: String,
    capa_command: String,
    pecli_command: String,
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
    //----------------------------------------------------------------------
    //------------------ TRID ----------------------------------------------
    // Get the full path
    let fullpath = fs::canonicalize(filepath.clone())
        .expect("Failed to get the full path");
    // Call the `trid` command to get file type
    let trid_command_output = Command::new("trid")
        .arg(&fullpath)
        .output()
        .expect("Failed to execute command");

    let filetype_trid = String::from_utf8_lossy(&trid_command_output.stdout).to_string();
    println!("{}", filetype_trid);
    // Extract the part after the filename and format it
    let formatted_filetype_trid: Vec<String> = filetype_trid
        .lines() // Split into lines
        .filter_map(|line| {
            // Check if the line contains a percentage (indicating a file type line)
            if line.contains('%') {
                // Return the entire line as it contains the percentage and file type info
                Some(line.trim().to_string()) // Trim whitespace and return the line
            } else {
                None
            }
        })
        .collect(); // Collect into a vector

    // Build the final output string
    let final_output = formatted_filetype_trid
        .iter()
        .enumerate()
        .map(|(i, info)| {
            if i < formatted_filetype_trid.len() - 1 {
                format!("{},", info) // Add a comma for all but the last item
            } else {
                info.clone() // Last item without a comma
            }
        })
        .collect::<Vec<String>>()
        .join("\n"); // Join with newlines

    // Update the original variable
    let filetype_trid = final_output;
    // -------------------------------------------------------    
    let md5 = md5::compute(&buffer);
    let sha256 = sha256_digest(&buffer);
    let sha1 = sha1::Sha1::digest(&buffer);
    let sha384 = sha2::Sha384::digest(&buffer);

    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, &buffer); 
    let humanhash = humanize(&uuid, 4);

    let fuzzy_hash = hash_file(&filepath); 
    let fuzzy_hash_str = match fuzzy_hash { Ok(fh) => fh.to_string(), Err(_) => String::from("N/A"), }; 

    // Call the `file` command to get file type
    let exiftool_command_output = Command::new("exiftool")
        .arg(&filepath)
        .output()
        .expect("Failed to execute command");

    let exiftool_command = String::from_utf8_lossy(&exiftool_command_output.stdout).to_string();

    let mut capa_command = String::new();
    let mut pecli_command = String::new();

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
        let pecli_command_output = Command::new("pecli")
            .arg("info")
            .arg(&filepath)
            // .arg("> capa_temp.txt")
            .output()
            .expect("Failed to execute command");
        
        // Capture the output of the command
        pecli_command = String::from_utf8_lossy(&pecli_command_output.stdout).to_string();


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
        filetype_trid: filetype_trid.trim().to_string(), // Use the output from the trid command
        md5: format!("{:x}", md5),
        sha256,
        sha1: format!("{:x}", sha1),
        sha384: format!("{:x}", sha384),
        humanhash, 
        fuzzy_hash: fuzzy_hash_str,
        capa_command,
        exiftool_command,
        pecli_command,
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
// integrare flarestrings <sample> | rank_strings
// integrare yara matching
// integrare yara rules

// tools for pdf files:
// https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py : 'Tool to test a PDF file'
// https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py : 'pdf-parser, use it to parse a PDF document'
// ? clamscan yourfile.pdf
// https://github.com/jesparza/peepdf/blob/master/peepdf.py

// tools for images:
// https://github.com/DidierStevens/DidierStevensSuite/blob/master/jpegdump.py : 'JPEG file analysis tool'

// tools for MS office documents:
// python-oletools https://github.com/decalage2/oletools
// Tools to analyze malicious documents

//     oleid: to analyze OLE files to detect specific characteristics usually found in malicious files.
//     olevba: to extract and analyze VBA Macro source code from MS Office documents (OLE and OpenXML).
//     MacroRaptor: to detect malicious VBA Macros
//     msodde: to detect and extract DDE/DDEAUTO links from MS Office documents, RTF and CSV
//     pyxswf: to detect, extract and analyze Flash objects (SWF) that may be embedded in files such as MS Office documents (e.g. Word, Excel) and RTF, which is especially useful for malware analysis.
//     oleobj: to extract embedded objects from OLE files.
//     rtfobj: to extract embedded objects from RTF files.

// Tools to analyze the structure of OLE files

//     olebrowse: A simple GUI to browse OLE files (e.g. MS Word, Excel, Powerpoint documents), to view and extract individual data streams.
//     olemeta: to extract all standard properties (metadata) from OLE files.
//     oletimes: to extract creation and modification timestamps of all streams and storages.
//     oledir: to display all the directory entries of an OLE file, including free and orphaned entries.
//     olemap: to display a map of all the sectors in an OLE file.

// Tools to analyze archive fiels:
//     p7zip-full
//     clamscan file.zip