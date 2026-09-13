//! Fresh-child bounded measurements over every executable real federated-corpus topology.
//!
//! The parent test starts one test-process child per question and topology. Each child opens its
//! topology, validates anchors, resets the peak window, executes exactly one question, then emits a
//! privacy-safe result census: topology and outcome class, never question, model, row, path or error.
//! RSS is a child-process high-water delta from the post-setup baseline; it is not a process-memory
//! bound, and pool peak is only the engine operator-reservation bound.

use std::num::NonZeroUsize;
use std::process::Command;

use super::corpus::{derived, every_question};
use super::{bundle, posture, source, tables_on};
use crate::adapters::{a_caller, shared_credential};
use sutura_domain::query::ToolOutcome;

const MEASURE_BOUNDS_CASE: &str = "MEASURE_BOUNDS_CASE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topology {
    One,
    Two,
}

impl Topology {
    const ALL: [Self; 2] = [Self::One, Self::Two];

    const fn label(self) -> &'static str {
        match self {
            Self::One => "one_source",
            Self::Two => "two_source",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Case {
    topology: Topology,
    question: usize,
}

impl Case {
    fn selected() -> Option<Self> {
        let value = match std::env::var(MEASURE_BOUNDS_CASE) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent | std::env::VarError::NotUnicode(_)) => return None,
        };
        let (topology, question) = value.split_once(':')?;
        let topology = Topology::ALL.into_iter().find(|candidate| candidate.label() == topology)?;
        let question = question.parse::<usize>().ok()?;
        Some(Self { topology, question })
    }

    fn selector(self) -> String {
        format!("{}:{}", self.topology.label(), self.question)
    }
}

fn cases() -> Vec<Case> {
    let questions = every_question().len();
    Topology::ALL
        .into_iter()
        .flat_map(|topology| (0..questions).map(move |question| Case { topology, question }))
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Census {
    answered: usize,
    refused: usize,
    failed: usize,
}

impl Census {
    fn record(&mut self, result: &Result<ToolOutcome, impl core::error::Error>, expected_failure: bool) {
        match result {
            Ok(ToolOutcome::Answer { .. }) => self.answered += 1,
            Ok(ToolOutcome::Refusal { .. }) => self.refused += 1,
            Err(error) if expected_failure => {
                let _ = error;
                self.failed += 1;
            }
            Err(error) => panic!("measurement child execution failed: {error}"),
        }
    }

    fn total(&self) -> usize {
        self.answered + self.refused + self.failed
    }
}

fn expected_failure(case: Case) -> bool {
    matches!(case.question, 23 | 34)
}

#[derive(Debug, PartialEq, Eq)]
struct Measurement {
    topology: Topology,
    census: Census,
    peak: usize,
    reserved: usize,
    rss: Option<usize>,
}

impl Measurement {
    fn json(&self) -> String {
        let rss = self.rss.map_or_else(|| String::from("null"), |bytes| bytes.to_string());
        let ratio = self.rss.map_or_else(
            || String::from("null"),
            |bytes| format!("{{\"numerator\":{},\"denominator\":{bytes}}}", self.peak),
        );
        let status = match self.census {
            Census {
                answered: 1,
                refused: 0,
                failed: 0,
            } => "ok",
            Census {
                answered: 0,
                refused: 1,
                failed: 0,
            } => "refused",
            Census {
                answered: 0,
                refused: 0,
                failed: 1,
            } => "failed",
            _ => "malformed",
        };
        format!(
            "{{\"status\":\"{status}\",\"topology\":\"{}\",\"peak\":{},\"reserved\":{},\"rss\":{},\"ratio\":{},\"answered\":{},\"refused\":{},\"failed\":{}}}",
            self.topology.label(),
            self.peak,
            self.reserved,
            rss,
            ratio,
            self.census.answered,
            self.census.refused,
            self.census.failed,
        )
    }
}

fn measured(source: sutura_domain::model::SourceName) -> sutura_exec_datafusion::measurement::MeasuredWarehouse {
    let ceiling = NonZeroUsize::new(1 << 30).expect("a gibibyte is positive");
    sutura_exec_datafusion::measurement::MeasuredWarehouse::new(
        source,
        posture(),
        sutura_exec_datafusion::WorkingSet::of_bytes(ceiling),
    )
    .expect("a measured engine starts")
}

fn measured_on(
    corpus: &super::corpus::Derived,
    source_name: &sutura_domain::model::SourceName,
    pinned: &sutura_domain::pinned::PinnedDefinitions,
) -> sutura_exec_datafusion::measurement::MeasuredWarehouse {
    let child = measured(source_name.clone());
    for (table, csv) in tables_on(&corpus.data, source_name, pinned) {
        child
            .attach_csv(&table, &csv)
            .unwrap_or_else(|_| panic!("measurement child could not attach a table"));
    }
    child
}

fn execute(case: Case) -> Measurement {
    let corpus = derived();
    let pinned = match case.topology {
        Topology::One => bundle(&corpus.one_source),
        Topology::Two => bundle(&corpus.two_source),
    };
    let one = measured_on(corpus, &source(), &pinned);
    let warehouses = match case.topology {
        Topology::One => sutura_app::Warehouses::of(one),
        Topology::Two => sutura_app::Warehouses::of(one)
            .and(measured_on(corpus, &super::lookup_source(), &pinned))
            .expect("two measured sources have different names"),
    };
    let bundle = sutura_app::verify_and_validate(pinned, &warehouses).expect("the measured topology validates");
    for (_, child) in warehouses.each() {
        child.reset_peak();
    }
    let baseline_rss = rss_high_water();
    let (_, question) = every_question()
        .into_iter()
        .nth(case.question)
        .expect("the measurement case names a corpus question");
    let mut census = Census::default();
    let result = sutura_app::answer(
        &bundle,
        &question,
        &a_caller(),
        &shared_credential(),
        &warehouses,
        super::BUDGET,
    )
    .map(sutura_app::Answered::into_outcome);
    census.record(&result, expected_failure(case));
    let rss = rss_high_water().and_then(|after| {
        let before = baseline_rss?;
        after.checked_sub(before)
    });
    let (peak, reserved) = warehouses.each().fold((0, 0), |(peak, reserved), (_, child)| {
        (peak.max(child.pool_peak()), reserved + child.pool_reserved())
    });
    Measurement {
        topology: case.topology,
        census,
        peak,
        reserved,
        rss,
    }
}

fn rss_high_water() -> Option<usize> {
    rss_high_water_from(&std::fs::read_to_string("/proc/self/status").ok()?)
}

fn rss_high_water_from(status: &str) -> Option<usize> {
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

fn run_child(case: Case) -> String {
    let output = Command::new(std::env::current_exe().expect("the test executable is known"))
        .arg("--exact")
        .arg("federated::bounds::every_corpus_question_has_one_fresh_child_outcome_in_each_topology")
        .arg("--nocapture")
        .env(MEASURE_BOUNDS_CASE, case.selector())
        .output()
        .expect("a measurement child starts");
    let stdout = String::from_utf8(output.stdout).expect("a measurement child writes UTF-8");
    assert!(output.status.success(), "a measurement child did not complete");
    let records: Vec<_> = stdout.lines().filter(|line| line.starts_with("{\"status\"")).collect();
    assert_eq!(records.len(), 1, "a measurement child emits one record");
    String::from(records[0])
}

#[test]
fn every_corpus_question_has_one_fresh_child_outcome_in_each_topology() {
    if let Some(case) = Case::selected() {
        let measurement = execute(case);
        println!("{}", measurement.json());
        assert_eq!(measurement.census.total(), 1, "one child executes one question");
        match measurement.census {
            Census {
                answered: 1,
                refused: 0,
                failed: 0,
            } => {
                assert!(measurement.peak > 0, "an answered query must reserve operator memory");
            }
            Census {
                answered: 0,
                refused: 1,
                failed: 0,
            }
            | Census {
                answered: 0,
                refused: 0,
                failed: 1,
            } => {}
            _ => panic!("a child has one valid outcome"),
        }
        return;
    }
    for case in cases() {
        println!("{}", run_child(case));
    }
}

#[test]
fn result_census_covers_each_question_once_per_topology() {
    let questions = every_question().len();
    let cases = cases();
    assert_eq!(cases.len(), questions * Topology::ALL.len());
    for topology in Topology::ALL {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.topology == topology)
            .map(|case| case.question)
            .collect();
        assert_eq!(selected, (0..questions).collect::<Vec<_>>());
    }
}

#[test]
fn widest_left_join_shape_executes_in_both_topologies() {
    let question = every_question()
        .iter()
        .position(|(name, _)| name == "two-source-a-same-source-orphan-beside-a-remote-one")
        .expect("the corpus contains the widest left-join shape");
    for topology in Topology::ALL {
        let record = run_child(Case { topology, question });
        assert!(record.contains("\"status\":\"ok\""), "{record}");
    }
}

#[test]
fn the_distinct_key_refusal_has_no_execution_peak() {
    let question = every_question()
        .iter()
        .position(|(name, _)| name == "two-source-a-distinct-value-spanning-join-keys")
        .expect("the corpus contains the distinct-key shape");
    let record = run_child(Case {
        topology: Topology::Two,
        question,
    });
    assert!(record.contains("\"status\":\"refused\""), "{record}");
    assert!(record.contains("\"peak\":0"), "{record}");
}

#[test]
fn rss_high_water_and_zero_ratio_are_machine_readable() {
    assert_eq!(rss_high_water_from("VmHWM:\t42 kB\n"), Some(42 * 1024));
    assert_eq!(rss_high_water_from("VmRSS:\t42 kB\n"), None);
    let record = Measurement {
        topology: Topology::Two,
        census: Census {
            answered: 0,
            refused: 1,
            failed: 0,
        },
        peak: 0,
        reserved: 0,
        rss: Some(42 * 1024),
    }
    .json();
    assert_eq!(
        record,
        "{\"status\":\"refused\",\"topology\":\"two_source\",\"peak\":0,\"reserved\":0,\"rss\":43008,\"ratio\":{\"numerator\":0,\"denominator\":43008},\"answered\":0,\"refused\":1,\"failed\":0}"
    );
}

#[test]
fn labels_are_machine_safe() {
    assert_eq!(Topology::One.label(), "one_source");
    assert_eq!(Topology::Two.label(), "two_source");
}
