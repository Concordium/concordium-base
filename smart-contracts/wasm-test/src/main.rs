use anyhow::{bail, ensure};
use clap::AppSettings;
use std::{collections::BTreeMap, fs, path::PathBuf};
use structopt::StructOpt;
use wasm_transform::{
    artifact::{Artifact, ArtifactNamedImport, CompiledFunction},
    machine::{ExecutionOutcome, Host, NoInterrupt, RunResult, RuntimeError, RuntimeStack, Value},
    parse::ParseError,
    types::{FunctionType, Module, Name},
    validate::ValidationError,
};
use wast::{parser, AssertExpression, Expression, Span, Wast, WastExecute};

#[derive(Debug, StructOpt)]
#[structopt(bin_name = "wasm-test")]
struct TestCommand {
    #[structopt(name = "dir", long = "dir", help = "Directory with .wast files")]
    dir:     PathBuf,
    #[structopt(name = "out", long = "out", help = "Directory where to output .wasm modules")]
    out_dir: Option<PathBuf>,
}

struct TrapHost;

#[derive(Debug)]
struct HostCallError {
    name: ArtifactNamedImport,
}

impl std::fmt::Display for HostCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Host function called {}", self.name)
    }
}

impl Host<ArtifactNamedImport> for TrapHost {
    type Interrupt = NoInterrupt;

    fn tick_initial_memory(&mut self, _num_pages: u32) -> RunResult<()> { Ok(()) }

    fn call(
        &mut self,
        f: &ArtifactNamedImport,
        _memory: &mut Vec<u8>,
        _stack: &mut RuntimeStack,
    ) -> RunResult<Option<NoInterrupt>> {
        bail!(HostCallError {
            name: f.clone(),
        })
    }
}

#[derive(Default)]
struct MeteringHost {
    call_depth:  i64,
    energy_left: u64,
}

impl Host<ArtifactNamedImport> for MeteringHost {
    type Interrupt = NoInterrupt;

    fn tick_initial_memory(&mut self, _num_pages: u32) -> RunResult<()> { Ok(()) }

    fn call(
        &mut self,
        f: &ArtifactNamedImport,
        _memory: &mut Vec<u8>,
        _stack: &mut RuntimeStack,
    ) -> RunResult<Option<NoInterrupt>> {
        if f.matches("concordium_metering", "track_call") {
            self.call_depth += 1;
            ensure!(self.call_depth <= 10000, "Call depth exceeded.");
        } else if f.matches("concordium_metering", "trac_return") {
            self.call_depth -= 1;
        } else if f.matches("concordium_metering", "account_energy") {
            self.energy_left -= 1;
        } else if f.matches("concordium_metering", "account_memory") {
        } else {
            bail!(HostCallError {
                name: f.clone(),
            })
        }
        Ok(None)
    }
}

fn validate(source: &[u8]) -> anyhow::Result<Module> {
    struct AllowAll;

    impl wasm_transform::validate::ValidateImportExport for AllowAll {
        fn validate_import_function(
            &self,
            _duplicate: bool,
            _mod_name: &Name,
            _item_name: &Name,
            _ty: &FunctionType,
        ) -> bool {
            true
        }

        fn validate_export_function(&self, _item_name: &Name, _ty: &FunctionType) -> bool { true }
    }

    let skel = wasm_transform::parse::parse_skeleton(source)?;
    wasm_transform::validate::validate_module(&AllowAll, &skel)
}

macro_rules! fail_test {
    ($span:expr, $name:expr, $input:expr, $message:expr) => {{
        let (line, col) = $span.linecol_in(&$input);
        // The +1 in line is because the line indexing as returned by linecol_in is
        // 0-based, but usually in editors it is 1-based
        bail!(ansi_term::Color::Red
            .paint(format!("{}: line: {}, column: {}, message: {}", $name, line + 1, col, $message))
            .to_string())
    }};
    ($b:expr => $span:expr, $name:expr, $input:expr, $message:expr) => {
        if $b {
            fail_test!($span, $name, $input, $message)
        }
    };
}

pub const DISALLOWED_INSTRUCTIONS: &[u8] = &[
    0x43, 0x44, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x8B, 0x8C,
    0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
    0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC,
    0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
    0xBD, 0xBE, 0xBF, 0xFC, // saturating truncation
    0x2A, 0x2B, 0xC0, 0xC2, 0xC3,
];

fn mk_values(exprs: &[Expression<'_>]) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    for e in exprs.iter() {
        if e.instrs.len() == 1 {
            match e.instrs[0] {
                wast::Instruction::I32Const(n) => out.push(Value::I32(n)),
                wast::Instruction::I64Const(n) => out.push(Value::I64(n)),
                _ => bail!("Unsupported argument instruction {:?}", e.instrs[0]),
            }
        } else {
            bail!("Unsupported length of argument expression.")
        }
    }
    Ok(out)
}

fn mk_results(exprs: &[AssertExpression<'_>]) -> anyhow::Result<Option<Value>> {
    if let Some(x) = exprs.first() {
        if exprs.len() <= 1 {
            match x {
                AssertExpression::I32(n) => Ok(Some(Value::I32(*n))),
                AssertExpression::I64(n) => Ok(Some(Value::I64(*n))),
                _ => bail!("Unsupported assert expression {:?}", x),
            }
        } else {
            bail!("Too many results.")
        }
    } else {
        Ok(None)
    }
}

fn invoke_update(
    artifact: &Artifact<ArtifactNamedImport, CompiledFunction>,
    name: &str,
    args: &[Value],
) -> anyhow::Result<Option<Value>> {
    match artifact.run(&mut TrapHost, name, args)? {
        ExecutionOutcome::Success {
            result,
            ..
        } => Ok(result),
        ExecutionOutcome::Interrupted {
            reason,
            ..
        } => match reason {}, // impossible case
    }
}

fn invoke_update_metering(
    artifact: &Artifact<ArtifactNamedImport, CompiledFunction>,
    name: &str,
    args: &[Value],
) -> anyhow::Result<Option<Value>> {
    let run = artifact.run(
        &mut MeteringHost {
            call_depth:  0,
            energy_left: 10000,
        },
        name,
        args,
    )?;
    match run {
        ExecutionOutcome::Success {
            result,
            ..
        } => Ok(result),
        ExecutionOutcome::Interrupted {
            reason,
            ..
        } => match reason {},
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        ansi_term::enable_ansi_support()?;
    }
    let cmd = {
        let app = TestCommand::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::TrailingVarArg)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        TestCommand::from_clap(&matches)
    };

    let success_style = ansi_term::Color::Green.bold();
    let warning_style = ansi_term::Color::Yellow;

    let mut success_counter = 0;

    let mut print_ok = || {
        success_counter += 1;
        eprintln!("{}", success_style.paint("OK"));
    };

    let print_omitted = || {
        eprintln!("{}", warning_style.paint("Omitted"));
    };

    let print_omitted_msg = |span: Span, input: &str, msg: &str| {
        let (line, col) = span.linecol_in(input);
        eprintln!("{}", warning_style.paint(format!("{}:{}:{} (Omitted)", line + 1, col, msg)));
    };

    let mut out_counter = 0;

    let mut maybe_output = |bytes: &[u8]| {
        if let Some(dir) = cmd.out_dir.as_ref() {
            let mut out_path = dir.clone();
            out_path.push(format!("{}.wasm", out_counter));
            std::fs::write(out_path, bytes).expect("Could not write the module.");
            out_counter += 1;
        }
    };

    for entry in fs::read_dir(&cmd.dir)?.filter_map(Result::ok) {
        let meta = entry.metadata()?;
        if meta.is_file() {
            if let Some("wast") = entry.path().extension().and_then(|s| s.to_str()) {
                let path = entry.path();
                let file_name = path.display();
                eprintln!("Processing file {}", file_name);
                let input = fs::read_to_string(&path)?;
                let source = parser::ParseBuffer::new(&input)?;
                let mut modules = BTreeMap::new();
                match parser::parse::<Wast>(&source) {
                    Ok(script) => {
                        for directive in script.directives {
                            match directive {
                                wast::WastDirective::Module(mut m) => {
                                    eprint!("  - Validating module ... ");
                                    let encoded = m.encode()?;
                                    maybe_output(&encoded);
                                    match validate(&encoded) {
                                        Ok(module) => {
                                            match module.compile::<ArtifactNamedImport>() {
                                                Ok(artifact) => {
                                                    modules.insert(
                                                        m.id.map(|x| x.name().to_string()),
                                                        Some(artifact.clone()),
                                                    );
                                                    modules.insert(None, Some(artifact));
                                                }
                                                Err(e) => fail_test!(
                                                    m.span,
                                                    file_name,
                                                    input,
                                                    format!("Error: {}", e)
                                                ),
                                            }
                                        }
                                        Err(e) => {
                                            modules
                                                .insert(m.id.map(|x| x.name().to_string()), None);
                                            modules.insert(None, None);
                                            if let Some(e) = e.downcast_ref::<ParseError>() {
                                                match e {
                                                    ParseError::UnsupportedInstruction {
                                                        opcode,
                                                    } => ensure!(
                                                        DISALLOWED_INSTRUCTIONS
                                                            .iter()
                                                            .any(|x| x == opcode),
                                                        "{}",
                                                        e
                                                    ),
                                                    ParseError::UnsupportedValueType {
                                                        byte,
                                                    } => ensure!(
                                                        *byte == 0x7D || *byte == 0x7C,
                                                        "{}",
                                                        e
                                                    ),
                                                    ParseError::UnsupportedImportType {
                                                        tag,
                                                    } => {
                                                        ensure!(
                                                            *tag == 0x01
                                                                || *tag == 0x02
                                                                || *tag == 0x03,
                                                            "{}",
                                                            e
                                                        );
                                                    }
                                                    ParseError::OnlySingleReturn => {}
                                                    ParseError::OnlyASCIINames => {}
                                                    ParseError::NameTooLong => {}
                                                    ParseError::FuncNameTooLong => {}
                                                    ParseError::StartFunctionsNotSupported => {}
                                                }
                                            } else if let Some(e) =
                                                e.downcast_ref::<ValidationError>()
                                            {
                                                match e {
                                                    ValidationError::TooManyLocals {
                                                        ..
                                                    } => {}
                                                }
                                            } else {
                                                bail!("Module {:?} not valid due to {}.", m.id, e)
                                            }
                                        }
                                    }
                                    print_ok();
                                }
                                wast::WastDirective::QuoteModule {
                                    ..
                                } => {
                                    // ignore
                                }
                                wast::WastDirective::AssertMalformed {
                                    module,
                                    message,
                                    span,
                                } => {
                                    eprint!("  - Validating invalid module ... ");
                                    match module {
                                        wast::QuoteModule::Module(mut m) => {
                                            let bytes = m.encode()?;
                                            maybe_output(&bytes);
                                            fail_test!(
                                                validate(&bytes).is_ok() =>
                                                span,
                                                file_name,
                                                input,
                                                message
                                            )
                                        }
                                        wast::QuoteModule::Quote(mods_bytes) => {
                                            for bytes in mods_bytes {
                                                fail_test!(
                                                    validate(&bytes).is_ok() =>
                                                    span,
                                                    file_name,
                                                    input,
                                                    message
                                                )
                                            }
                                        }
                                    }
                                    print_ok();
                                }
                                wast::WastDirective::AssertInvalid {
                                    span,
                                    mut module,
                                    message,
                                } => {
                                    let bytes = module.encode()?;
                                    maybe_output(&bytes);
                                    fail_test!(
                                        validate(&bytes).is_ok() =>
                                        span,
                                        file_name,
                                        input,
                                        message
                                    )
                                }
                                wast::WastDirective::Register {
                                    ..
                                } => {
                                    // we don't support linking, so registering
                                    // is not useful.
                                }
                                wast::WastDirective::Invoke(a) => {
                                    eprint!("  - Invoke ... ");
                                    if let Some(Some(artifact)) =
                                        modules.get(&a.module.map(|x| x.name().to_string()))
                                    {
                                        if artifact.imports.is_empty() {
                                            if let Ok(values) = mk_values(&a.args) {
                                                ensure!(
                                                    invoke_update(artifact, a.name, &values)
                                                        .is_ok(),
                                                    "Invoke failed."
                                                )
                                            }
                                        }
                                        print_ok();
                                    } else {
                                        print_omitted();
                                    }
                                }
                                wast::WastDirective::AssertTrap {
                                    span,
                                    exec,
                                    message,
                                } => {
                                    eprint!("  - Assert trap ");
                                    match exec {
                                        wast::WastExecute::Invoke(invoke) => {
                                            if let Some(Some(artifact)) = modules.get_mut(
                                                &invoke.module.map(|x| x.name().to_string()),
                                            ) {
                                                if let Ok(values) = mk_values(&invoke.args) {
                                                    fail_test!(
                                                        invoke_update(
                                                            artifact,
                                                            invoke.name,
                                                            &values
                                                        )
                                                        .is_ok() =>
                                                        span,
                                                        file_name,
                                                        input,
                                                        message
                                                    )
                                                }
                                                print_ok();
                                            } else {
                                                print_omitted_msg(span, &input, message)
                                            }
                                        }
                                        wast::WastExecute::Module(_module) => {
                                            // unsupported, this has to do with
                                            // linking, and start functions,
                                            // which we
                                            // do not supported
                                        }
                                        wast::WastExecute::Get {
                                            ..
                                        } => {
                                            // unsupported
                                        }
                                    }
                                }
                                wast::WastDirective::AssertReturn {
                                    span,
                                    exec,
                                    results,
                                } => {
                                    eprint!("  - Assert return ... ");
                                    if let WastExecute::Invoke(invoke) = exec {
                                        let expected = mk_results(&results);
                                        match expected {
                                            Ok(expected) if results.len() <= 1 => {
                                                if let Some(Some(artifact)) = modules.get_mut(
                                                    &invoke.module.map(|x| x.name().to_string()),
                                                ) {
                                                    if let Ok(values) = mk_values(&invoke.args) {
                                                        match invoke_update(
                                                            artifact,
                                                            invoke.name,
                                                            &values,
                                                        ) {
                                                            Ok(v) => fail_test!(
                                                                v != expected =>
                                                                span,
                                                                file_name,
                                                                input,
                                                                format!(
                                                                    "Calling {}: {:?} != {:?}",
                                                                    invoke.name, v, expected
                                                                )
                                                            ),
                                                            Err(e) => {
                                                                if let Some(x) =
                                                                    e.downcast_ref::<RuntimeError>()
                                                                {
                                                                    match x {
                                                                RuntimeError::DirectlyCallImport => {
                                                                    // OK, this is our own restriction.
                                                                }
                                                            }
                                                                } else if e
                                                                    .downcast_ref::<HostCallError>()
                                                                    .is_some()
                                                                {
                                                                    // OK, this is
                                                                    // our
                                                                    // restriction
                                                                } else {
                                                                    fail_test!(
                                                                        span,
                                                                        file_name,
                                                                        input,
                                                                        format!(
                                                                            "Calling {}: {}",
                                                                            invoke.name,
                                                                            e.to_string()
                                                                        )
                                                                    )
                                                                }
                                                            }
                                                        }
                                                        print_ok();
                                                    } else {
                                                        print_omitted_msg(
                                                            span,
                                                            &input,
                                                            "Unsupported input types.",
                                                        );
                                                    }
                                                } else {
                                                    print_omitted_msg(
                                                        span,
                                                        &input,
                                                        "Unsupported module.",
                                                    );
                                                }
                                            }
                                            _ => print_omitted_msg(
                                                span,
                                                &input,
                                                "Unsupported types or multiple return values.",
                                            ),
                                        }
                                    } else {
                                        print_omitted_msg(
                                            span,
                                            &input,
                                            "Unsupported module invocation.",
                                        );
                                    }
                                }
                                wast::WastDirective::AssertExhaustion {
                                    span,
                                    call,
                                    message,
                                } => {
                                    eprint!("Assert exhaustion ... ");
                                    if let Some(Some(artifact)) =
                                        modules.get_mut(&call.module.map(|x| x.name().to_string()))
                                    {
                                        if let Ok(values) = mk_values(&call.args) {
                                            fail_test!(
                                                invoke_update_metering(
                                                    artifact, call.name, &values
                                                )
                                                .is_ok() =>
                                                span,
                                                file_name,
                                                input,
                                                message
                                            )
                                        } else {
                                            print_ok()
                                        }
                                    } else {
                                        print_omitted_msg(span, &input, message);
                                    }
                                }
                                wast::WastDirective::AssertUnlinkable {
                                    ..
                                } => {
                                    // skip these since we do not support
                                    // dependencies.
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("Could not parse test file: {}", e),
                }
            }
        }
    }
    eprintln!("Successful tests: {}.", success_counter);
    Ok(())
}
