use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use regex::Regex;
use clap::{Parser, Subcommand};
use envs::get_environment_info;

/// Rust Env Tool with Subst and Info functionalities.
#[derive(Parser)]
#[command(
    name = "rust-env-tool",
    about = "A tool for environment variable substitution and displaying environment information",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Substitute environment variables in the input
    Subst {
        /// Input file. If not provided, read from standard input
        #[arg(short, long, value_name = "FILE")]
        input: Option<String>,

        /// Output file. If not provided, write to standard output
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },
    /// Display environment information
    Info,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Subst { input, output } => {
            handle_subst(input, output)?;
        }
        Commands::Info => {
            handle_info();
        }
    }

    Ok(())
}

/// Handles the `Subst` subcommand, performing environment variable substitution.
fn handle_subst(input: &Option<String>, output: &Option<String>) -> io::Result<()> {
    // Read input content from a file or standard input
    let mut input_content = String::new();
    if let Some(input_file) = input {
        let mut file = File::open(input_file)?;
        file.read_to_string(&mut input_content)?;
    } else {
        io::stdin().read_to_string(&mut input_content)?;
    }

    // Define a regex pattern to match $VAR, ${VAR}, ${VAR:-default}, ${VAR-default}, etc.
    let re = Regex::new(r"\$\{(\w+)(?:(:?[-+=])(?:(.*?))?)?\}|\$(\w+)").unwrap();

    // Perform substitution based on the matched patterns
    let result = re.replace_all(&input_content, |caps: &regex::Captures| {
        if let Some(var) = caps.get(1) {
            let var_name = var.as_str();
            let operator = caps.get(2).map_or("", |m| m.as_str());
            let value = caps.get(3).map_or("", |m| m.as_str());

            match operator {
                ":-" => {
                    // Use variable value if set; otherwise, use the default value
                    env::var(var_name).unwrap_or_else(|_| value.to_string())
                }
                "-" => {
                    // Use variable value if set; otherwise, use the default value
                    env::var(var_name).unwrap_or_else(|_| value.to_string())
                }
                ":=" => {
                    // If the variable is not set or empty, set it to the default value and use it
                    match env::var(var_name) {
                        Ok(val) if !val.is_empty() => val,
                        _ => {
                            env::set_var(var_name, value);
                            value.to_string()
                        }
                    }
                }
                "=" => {
                    // If the variable is not set, set it to the default value and use it
                    match env::var(var_name) {
                        Ok(val) => val,
                        _ => {
                            env::set_var(var_name, value);
                            value.to_string()
                        }
                    }
                }
                ":+ " => {
                    // If the variable is set and not empty, use the specified value; otherwise, use an empty string
                    match env::var(var_name) {
                        Ok(val) if !val.is_empty() => value.to_string(),
                        _ => "".to_string(),
                    }
                }
                ":?" => {
                    // If the variable is not set or empty, print an error message and exit
                    match env::var(var_name) {
                        Ok(val) if !val.is_empty() => val,
                        _ => {
                            eprintln!("Error: {}", value);
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    // Use the variable value if set; otherwise, use an empty string
                    env::var(var_name).unwrap_or_else(|_| "".to_string())
                }
            }
        } else if let Some(var) = caps.get(4) {
            // Handle $VAR
            let var_name = var.as_str();
            env::var(var_name).unwrap_or_else(|_| "".to_string())
        } else {
            // If no variable matched, keep the original string
            caps.get(0).map_or("", |m| m.as_str()).to_string()
        }
    });

    // Write the result to a file or standard output
    if let Some(output_file) = output {
        let mut file = File::create(output_file)?;
        file.write_all(result.as_bytes())?;
    } else {
        io::stdout().write_all(result.as_bytes())?;
    }

    Ok(())
}

/// Handles the `Info` subcommand, displaying environment information.
fn handle_info() {
    let info = get_environment_info();

    println!("Operating System: {}", info.os);
    println!("Container Environment: {}", info.container);
    println!("Virtualization Platform: {}", info.virtualization);

    if let Some(caps) = &info.capabilities {
        println!("Capabilities:");
        for cap in &caps.effective {
            println!("  - {}", cap);
        }
    } else {
        println!("Capabilities: Not Available or Not Applicable");
    }
}
