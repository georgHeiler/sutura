use std::path::PathBuf;

use super::provenance::Commit;
use super::worktree::at_base;

fn one_commit_in_a_scratch_repo() -> (PathBuf, Commit) {
    let dir = std::env::temp_dir().join(format!("sutura-causality-base-content-{}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(dir.join("src")).expect("a scratch tree");
    std::fs::write(dir.join("src/a.rs"), "pub fn one() -> u8 {\n    1\n}\n").expect("a module");
    let git = |args: &[&str]| {
        let mut command = std::process::Command::new("git");
        crate::repo::strip_git_env(&mut command);
        let out = command.current_dir(&dir).args(args).output().expect("git runs");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["add", "-A"]);
    git(&[
        "-c",
        "user.email=user@example.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "base",
    ]);
    let base = Commit::parse(&git(&["rev-parse", "HEAD"])).expect("an object name");
    (dir, base)
}

#[test]
fn a_failed_base_content_read_is_not_an_absent_path() {
    let (dir, base) = one_commit_in_a_scratch_repo();
    let unknown = Commit::parse("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").expect("an object name");
    let failed = at_base(&dir, &unknown, "src/a.rs");
    let absent = at_base(&dir, &base, "src/none.rs");
    drop(std::fs::remove_dir_all(&dir));
    assert!(failed.is_err(), "a failed git show must refuse: {failed:?}");
    assert!(matches!(absent, Ok(None)), "an absent path remains an answer: {absent:?}");
}
