#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate regex;

use ansi_term::Color::*;
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::Command;
use std::str;

#[derive(Clap)]
#[clap()]
struct NannyOpts {
    #[clap(short = "c")]
    changelist: Option<String>,

    #[clap(short = "w")]
    workspace: Option<String>,

    #[clap(short = "r")]
    root_path: String,

    #[clap(short = "v")]
    verbose: bool,

    #[clap()]
    use_color: bool,
}

enum Severity {
    Info,
    MildWarning,
    Warning,
    Error,
    HeavyError,
}

/// Check for invalid "TODO" lines.
///
/// We don't allow checking in "TODOs" unless they are formatted
/// in a very specific way. And this regex _should_ be able to
/// find invalid occurences of "TODO". It only checks if a given
/// line of text _is_ a valid TODO, however, so the initial
/// "this is a TODO we should check" needs to be done first for
/// each line in the file.
fn check_todo_format(line: &str) -> Result<(), ()> {
    lazy_static! {
        static ref TODO_RE: Regex = Regex::new(
            r"TODO: \(https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]([-a-zA-Z0-9()@:%_\+.~#?&/=]*)\)"
        )
        .unwrap();
    }
    if TODO_RE.is_match(line) {
        return Ok(());
    }

    Err(())
}

/// Check for C-style casts in code.
///
/// We don't like them, and we shouldn't use them.
/// This is a simple regex check and will almost certainly
/// yiled false positives.
fn check_cstyle_cast(line: &str) -> Result<(), ()> {
    lazy_static! {
        static ref CCAST_RE: Regex = Regex::new(r"\(.+\)\s?[a-zA-Z]").unwrap();
    }

    Err(())
}

/// Try to detect lines of commented code.
///
/// This is known to produce false-positives, so take the
/// results with a grain of salt until/unless I beef it
/// up a bit.
fn check_commented_code(line: &str) -> Result<(), ()> {
    // TODO: Check for more kinds of commented code, like open braces at the end?
    lazy_static! {
        static ref COMCODE_RE: Regex = Regex::new(r"^\s*//.*[;{]\s*(//.*)?$").unwrap();
    }

    if COMCODE_RE.is_match(line) {
        return Err(());
    }

    Ok(())
}

/// Make sure each "case" ends in a break, not an early return.
///
/// That is, early returns are fine, the whole case just needs
/// to _also_ have a 'break' at the end, as a step to prevent
/// unintentional fallthrough bugs should your early return be
/// removed at some point in the future and not replaced with
/// a 'break'.
///
/// Because this requires some state from line-to-line, we use
/// a struct to contain the needed data, and the check is a
/// function on that data structure.

pub enum LastSwitchLineType {
    None,
    Switch,
    Case,
    Break,
    Return,
    Other,
}

pub struct CaseChecker {
    case_start: usize,
    paren_count: usize,
    all_lines: Vec<String>,
    // in_switch: bool,
    case_line: String,
    last_line: LastSwitchLineType,
}

impl CaseChecker {
    pub fn new() -> Self {
        CaseChecker {
            case_start: 0,
            paren_count: 0,
            all_lines: vec![],
            // in_switch: false,
            case_line: "".to_owned(),
            last_line: LastSwitchLineType::None,
        }
    }

    pub fn check_line(&mut self, line: &str, num: usize) -> Result<(), (usize, String)> {
        // Accumulate lines when a "case" is found, and end when
        // another "case" is found, or "default" or a close parenthesis
        // that wasn't opened since the start.
        lazy_static! {
            static ref CASE_RX: Regex = Regex::new("case.+:").unwrap();
        }

        if line.contains(r"switch") {
            // self.in_switch = true;
            self.last_line = LastSwitchLineType::Switch;
        }

        // // Leave this check if we're not in a switch
        // if !self.in_switch {
        //     return Ok(());
        // }

        // line.chars().for_each(|c| {
        //     if c == '{' {
        //         self.paren_count += 1;
        //     }
        //     if c == '{' {
        //         self.paren_count -= 1;
        //     }
        // });

        // if (self.paren_count == 0)

        if line.contains(r"return") {
            self.last_line = LastSwitchLineType::Return;
            // println!("Found RETURN");
        }

        if line.contains(r"break") {
            self.last_line = LastSwitchLineType::Break;
            // println!("Found BREAK");
        }

        if CASE_RX.is_match(line) {
            let flagged = match &self.last_line {
                LastSwitchLineType::Return => true,
                _ => false,
            };

            let old_start = self.case_start;
            let old_text = self.case_line.clone();

            self.case_start = num;
            self.paren_count = 0;
            self.all_lines.clear();
            self.case_line = line.to_owned();

            if flagged {
                return Err((old_start + 1, old_text.into()));
            }
        }

        if line.contains("default:") {
            let flagged = match &self.last_line {
                LastSwitchLineType::Return => true,
                _ => false,
            };

            if flagged {
                return Err((self.case_start, self.case_line.clone().into()));
            }
        }

        Ok(())
    }
}

/// Go through each line of a file and check for simple things,
/// and/or hand off the line to a more robust checking function.
fn check_file(text: &String) -> Vec<(Severity, String)> {
    let mut case_checker = CaseChecker::new();
    let mut found_issues = Vec::<(Severity, String)>::new();

    for (idx, line) in text.lines().enumerate() {
        let line_num = idx + 1;
        if line.contains("XXX:") {
            found_issues.push((
                Severity::HeavyError,
                format!("    (XXX NOTE) || Line ({}) || {}", line_num, line.trim()),
            ));
            continue;
        }
        if line.contains("TODO") {
            let todo_check = check_todo_format(line);
            match todo_check {
                Err(_) => {
                    found_issues.push((
                        Severity::Error,
                        format!("    (BAD TODO) || Line ({}) || {}", line_num, line.trim()),
                    ));
                }
                _ => {}
            }
            continue;
        }

        if line.contains("#pragma optimize") {
            found_issues.push((
                Severity::Warning,
                format!(
                    "    (REMOVE PRAGMA) || Line ({}) || {}",
                    line_num,
                    line.trim()
                ),
            ));
            continue;
        }

        if check_commented_code(line).is_err() {
            found_issues.push((
                Severity::Warning,
                format!(
                    "    COMMENTED CODE || Line ({}) || {}",
                    line_num,
                    line.trim()
                ),
            ));
            continue;
        }

        if let Err((line_num, line_text)) = case_checker.check_line(line, line_num) {
            // println!("Checking for case...?");
            found_issues.push((
                Severity::MildWarning,
                format!(
                    "    CASE WITHOUT BREAK || Line ({}) || {}",
                    line_num, line_text
                ),
            ));
            continue;
        }
    }
    found_issues
}

fn print_line(severity: Severity, line: String, use_color: bool) {
    if use_color {
        match severity {
            Severity::Info => println!("{}", Green.paint(line)),
            Severity::MildWarning => println!("{}", Blue.paint(line)),
            Severity::Warning => println!("{}", Yellow.paint(line)),
            Severity::Error => println!("{}", Red.paint(line)),
            Severity::HeavyError => println!("{}", Purple.paint(line)),
        }
    } else {
        println!("{}", line)
    }
}

/// Main
fn main() -> std::io::Result<()> {
    println!("Source Nanny {}", env!("CARGO_PKG_VERSION"));

    let opts = NannyOpts::parse();
    println!("Root = {:?}", opts.root_path);
    println!("Changelist = {:?}", opts.changelist);
    println!("Workspace = {:?}", opts.workspace);

    let root_path = opts.root_path;
    let changelist = opts.changelist.unwrap();
    let workspace = opts.workspace.unwrap();

    let p4_output = Command::new("p4")
        .args(&["-ztag", "opened", "-c", &changelist])
        .output()
        .expect("failed to execute p4 command");

    let out_string = str::from_utf8(&p4_output.stdout).unwrap();

    let mut total_issues = 0usize;
    let mut files_count = 0usize;

    let expected_inital_line = "... clientFile //";

    for line in out_string.lines() {
        if line.starts_with(expected_inital_line) {
            let start = expected_inital_line.len();
            // let end = line.find("#").unwrap();
            let partial_path = &line[start..];
            // let path = format!("{}/{}", opts.root_path, partial_path);
            let path = partial_path.replace(&workspace, &root_path);
            let file_op = File::open(&path);

            let file = match file_op {
                Ok(f) => f,
                Err(_) => {
                    if opts.verbose {
                        println!("Error opening file: {}", path);
                    }
                    continue;
                }
            };
            files_count += 1;

            let mut buf_reader = BufReader::new(file);
            let mut contents = String::new();
            match buf_reader.read_to_string(&mut contents) {
                Ok(_) => {}
                Err(_) => {
                    if opts.verbose {
                        println!("Skipping non-text file: {}", &path);
                    }
                    continue;
                }
            };
            let found_issues = check_file(&contents);
            if found_issues.len() > 0 {
                total_issues += found_issues.len();
                println!("{} Issues found in file:\n[{}]", found_issues.len(), path);
                for (severity, issue) in found_issues {
                    print_line(severity, issue, opts.use_color);
                }
            }
        } else {
            if opts.verbose {
                print_line(
                    Severity::Info,
                    format!("Skipping line: {}", line),
                    opts.use_color,
                );
            }
        }
    }

    println!(
        "DONE!\nChecked {} file(s) with {} issue(s) found.",
        files_count, total_issues
    );

    Ok(())
}
