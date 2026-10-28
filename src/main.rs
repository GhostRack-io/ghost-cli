use std::{
    io::{self, Write as _},
    process::ExitCode,
};

use ghost::{OutputFormat, Terminal};

fn main() -> ExitCode {
    ghost::dispatch();
    runtime_main()
}

#[tokio::main]
async fn runtime_main() -> ExitCode {
    let cli = ghost::parse();
    // `ghost x`, `ghost mcp` and `ghost ghostd job logs` write their own
    // output and choose their exit code.
    #[cfg(unix)]
    if let Some(code) = ghost::run_direct(&cli).await {
        return ExitCode::from(code);
    }
    // `ghost instance console` runs ssh, which has the terminal.
    #[cfg(unix)]
    if let Some(code) = ghost::run_console(&cli).await {
        return ExitCode::from(code);
    }
    let format = cli.output_format();
    match ghost::execute(&cli).await {
        Ok(output) => match print(&ghost::render_result(&cli, &output, Terminal::stdout())) {
            Ok(()) => {
                for line in ghost::closing_notes(&cli, &output).await {
                    let _ = writeln!(io::stderr(), "{line}");
                }
                ExitCode::SUCCESS
            }
            // The reader stopped reading, as `head` does; it has what it wanted.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr(), "Error: cannot write the result: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            // A waited job that failed still prints its final snapshot;
            // with JSON output, any other failure prints an error object.
            if let Some(failed) = error.downcast_ref::<ghost::JobUnsuccessful>() {
                let _ = print(&ghost::render_output(
                    failed.snapshot(),
                    format,
                    Terminal::stdout(),
                ));
            } else if format != OutputFormat::Readable {
                let _ = print(&ghost::render_output(
                    &ghost::error_output(&error),
                    format,
                    Terminal::stdout(),
                ));
            }
            let _ = writeln!(
                io::stderr(),
                "{}",
                ghost::render_error(&error, Terminal::stderr())
            );
            ExitCode::FAILURE
        }
    }
}

/// Write `text` and a newline to standard output. Unlike `println!`, a
/// failed write is returned instead of panicking.
fn print(text: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()
}
