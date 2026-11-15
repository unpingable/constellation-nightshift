"""Bounded source-shape gate, not a Rust parser or runtime qualification.

The modern NQ-ng interfaces remain read-only replay ports. Restrict their whole
subprocess expression, including argument order and process modifiers. Runtime
cross-office qualification remains separate from this structural source check.
The separately enrolled saved-check acquisition port is not read-only replay.
"""

import pathlib
import re
import sys


def check(source, operation):
    # Preserve string bytes; ignore only whitespace outside string literals.
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s]', source)
    compact = "".join(tokens)
    expected = (
        'Command::new(&self.program).args(['
        f'"{operation}","replay",'
        '"--profile",&profile.path().to_string_lossy(),'
        '"--evidence",&evidence.path().to_string_lossy(),'
        '"--receipt",&receipt.path().to_string_lossy(),'
        '"--output","-",]).output().map_err('
    )
    if compact.count('Command::new') != 1 or expected not in compact:
        return False
    pin = 'ifprogram.file_name().and_then(|name|name.to_str())!=Some("nq"){returnErr('
    return pin in compact


def saved_check_production(source):
    """Recognize this source's terminal test module, not field-level cfg(test).

    This is a conservative source-shape check, not a Rust parser. New raw
    strings or block comments require review rather than guessed tokenization.
    """
    if re.search(r'\br#*"|/\*', source):
        return None
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|//[^\n]*|[^\s]', source)
    tokens = [token for token in tokens if not token.startswith('//')]
    compact = ''.join(tokens)
    marker = '#[cfg(test)]modtests{'
    if compact.count(marker) != 1:
        return None
    prefix, tests = compact.split(marker)
    # A new production item after the test module must not be hidden either.
    depth = 1
    test_tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s]', tests)
    for index, token in enumerate(test_tokens):
        if token == '{':
            depth += 1
        elif token == '}':
            depth -= 1
        if depth == 0:
            return prefix if index == len(test_tokens) - 1 else None
    return None


def check_saved_check(source):
    production = saved_check_production(source)
    if production is None:
        return False
    # One process site, called by exactly the enrolled Monitor and NQ adapters;
    # four named NQ operations, never an arbitrary configured verb vector.
    for text, count in (('Command::new', 1), ('run_bounded(', 3), ('nq_json(', 5)):
        if production.count(text) != count:
            return False
    required = (
        ('run', '''run_bounded(&config.monitor_program,&config.monitor_program_sha256,None,
           &["collect".into(),config.monitor_project.as_os_str().into(),
           "--trusted-root".into(),config.monitor_trusted_root.as_os_str().into(),
           "--allow-exec".into(),"--json".into(),],config.command_timeout_seconds,)?'''),
        ('nq_json', '''run_bounded(&config.nq_program,&config.nq_program_sha256,
           Some((&config.nq_config,&config.nq_config_sha256)),&args,config.command_timeout_seconds,)?'''),
        ('nq_json', '''let mut args=vec!["--config".into(),config.nq_config.as_os_str().into(),"--json".into(),];
           args.extend(tail.iter().map(|argument|std::ffi::OsString::from(*argument)),);
           let output=run_bounded(&config.nq_program,&config.nq_program_sha256,
           Some((&config.nq_config,&config.nq_config_sha256)),&args,config.command_timeout_seconds,)?;'''),
        ('verify_definition', '''nq_json(config,&["saved-check","inspect",&config.definition_reference],)?'''),
        ('resume', '''nq_json(config,&["saved-check","result","--evaluation-id",&record.evaluation_id,],)?'''),
        ('resume', '''nq_json(config,&["saved-check","evaluate",&config.definition_reference,
           "--evaluation-id",&record.evaluation_id,"--target",config.saved_check_target.to_str()
           .ok_or("saved-check target is not UTF-8")?,"--source-observed-at",
           record.source_observed_at.as_deref().ok_or("source observation absent")?,],)'''),
        ('finish', '''nq_json(config,&["saved-check","condition","--evaluation-id",&record.evaluation_id,
           "--component",&config.condition_component,"--kind",&config.condition_kind,
           "--subject",&config.condition_subject,"--at",&at_text,],)?'''),
        ('run_bounded', '''let executable=capture_sealed(program,program_digest,MAX_PROGRAM_BYTES,true)?;'''),
        ('run_bounded', '''let config_capture=config.map(|(path,digest)|capture_sealed(path,digest,MAX_CONFIG_BYTES,false)).transpose()?;'''),
        ('run_bounded', '''let executable_path=format!("/proc/self/fd/{}",executable.as_raw_fd());'''),
        ('run_bounded', '''let config_path=config_capture.as_ref().map(|file|std::ffi::OsString::from(format!("/proc/self/fd/{}",file.as_raw_fd())));'''),
        ('run_bounded', '''let args:Vec<_>=args.iter().map(|arg|{
           if config.is_some_and(|(path,_)|arg==path.as_os_str()){
           config_path.clone().expect("captured config path")}else{arg.clone()}}).collect();
           let stdout=tempfile::tempfile().map_err(|e|e.to_string())?;
           let stderr=tempfile::tempfile().map_err(|e|e.to_string())?;
           let mut child=Command::new(executable_path)'''),
        ('run_bounded', '''Command::new(executable_path).args(args).process_group(0).stdin(Stdio::null())
           .stdout(Stdio::from(stdout.try_clone().map_err(|e|e.to_string())?))
           .stderr(Stdio::from(stderr.try_clone().map_err(|e|e.to_string())?))
           .spawn().map_err(|e|format!("cannot start saved-check role: {e}"))?'''),
        (None, '''const MAX_CONFIG_BYTES:u64=64*1024;'''),
        (None, '''const MAX_RESULT_BYTES:u64=1024*1024;'''),
        (None, '''const MAX_PROGRAM_BYTES:u64=1024*1024*1024;'''),
        ('run', '''config.validate()?;'''),
        ('validate', '''if !(1..=300).contains(&self.command_timeout_seconds){return Err("command_timeout_seconds must be in 1..=300".into());}'''),
        ('run_bounded', '''let deadline=Instant::now()+Duration::from_secs(seconds);'''),
        ('run_bounded', '''if stdout_len>MAX_RESULT_BYTES||stderr_len>MAX_RESULT_BYTES{
           stop_child_group(&mut child);return Err("saved-check role exceeded its output bound".into());}'''),
        ('run_bounded', '''if Instant::now()>=deadline{stop_child_group(&mut child);
           return Err("saved-check role exceeded its bounded runtime".into());}'''),
        ('run_bounded', '''};kill_process_group(child.id());#[cfg(test)]let stderr=read_file(stderr,MAX_RESULT_BYTES)?;'''),
        ('run_bounded', '''#[cfg(not(test))]read_file(stderr,MAX_RESULT_BYTES)?;'''),
        ('run_bounded', '''stdout:read_file(stdout,MAX_RESULT_BYTES)?,'''),
        ('read_file', '''fn read_file(mut file:File,max:u64)->Result<Vec<u8>,String>{
           file.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
           let mut out=Vec::new();file.take(max+1).read_to_end(&mut out).map_err(|e|e.to_string())?;
           if out.len() as u64>max{return Err("saved-check input exceeds byte bound".into());}Ok(out)}'''),
        ('capture_sealed', '''let mut source=open_bounded_descriptor(path,max,executable)?;'''),
        ('capture_sealed', '''libc::memfd_create(name.as_ptr(),libc::MFD_ALLOW_SEALING)'''),
        ('capture_sealed', '''if copied>max{return Err("saved-check deployment input exceeds its bound".into());}'''),
        ('capture_sealed', '''if actual!=expected{return Err("saved-check runtime deployment digest mismatch".into());}'''),
        ('capture_sealed', '''if unsafe{libc::fchmod(captured.as_raw_fd(),0o500)}!=0{
           return Err(std::io::Error::last_os_error().to_string());}'''),
        ('capture_sealed', '''let seals=libc::F_SEAL_WRITE|libc::F_SEAL_SHRINK|libc::F_SEAL_GROW|libc::F_SEAL_SEAL;'''),
        ('capture_sealed', '''if unsafe{libc::fcntl(captured.as_raw_fd(),libc::F_ADD_SEALS,seals)}!=0{
           return Err(std::io::Error::last_os_error().to_string());}'''),
        ('open_bounded_descriptor', '''.custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK)'''),
        ('open_bounded_descriptor', '''if !metadata.file_type().is_file()||metadata.len()>max{
           return Err("saved-check deployment input must be a bounded regular file".into());}'''),
        ('kill_process_group', '''libc::kill(-pid,libc::SIGKILL);'''),
        ('stop_child_group', '''fn stop_child_group(child:&mut std::process::Child){kill_process_group(child.id());let _=child.wait();}'''),
    )
    for function, shape in required:
        scope = production if function is None else saved_check_function(production, function)
        expected = ''.join(re.findall(r'"(?:\\.|[^"\\])*"|[^\s]', shape))
        if scope is None or scope.count(expected) != 1:
            return False
    return True


def saved_check_function(production, name):
    """Scope each witness to its named function; another caller cannot satisfy it."""
    marker = 'fn' + name + '('
    if name == 'capture_sealed':
        marker = '#[cfg(target_os="linux")]' + marker
    if production.count(marker) != 1:
        return None
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s]', production.split(marker)[1])
    opened = False
    depth = 0
    for index, token in enumerate(tokens):
        if token == '{':
            opened = True
            depth += 1
        elif token == '}':
            depth -= 1
        if opened and depth == 0:
            return marker + ''.join(tokens[:index + 1])
    return None


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    failed = False
    for module, operation in (
        ("repository_qualification", "campaign-stage-qualification"),
        ("reservation_qualification", "campaign-stage-realization"),
    ):
        source = root / "crates/nightshiftd/src" / f"{module}.rs"
        if not check(source.read_text(), operation):
            print(f"restricted replay check failed: {module}", file=sys.stderr)
            failed = True
    source = root / "crates/nightshiftd/src/saved_check_runtime.rs"
    if not check_saved_check(source.read_text()):
        print("restricted saved-check acquisition port changed", file=sys.stderr)
        failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
