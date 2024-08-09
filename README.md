# Artifacts of the paper "DogeFuzz: A Simple Yet Efficient Grey-box Fuzzer for Smart Contracts."

This repository contains artifacts for the experiments in the paper DogeFuzz: A Simple Yet Efficient Grey-box Fuzzer for Smart Contracts. The `dataset` directory includes two benchmarks: Bench72 and Bench500. The other directories are `dogefuzz-results` for processing Dogefuzz-related result files and `Smartian-Artifact` for processing Smartian-related replication studies.

All commands are executed from inside `dogefuzz-results` directory.

## Processing the 5-runs campaign data of Dogefuzz:

1. install Poetry:

```
$ curl -sSL https://install.python-poetry.org | python3 -
```

2. change directory to the dogefuzz-results module:

```
$ cd dogefuzz-results
```

3. from inside dogefuzz-results directory, install all dependdencies using poetry:

```
$ poetry install
```

4. run the report generator for each campaign, execute the following commands:

```
$ cd dogefuzz-results

$ poetry run aggregator generate_report_smartian sbes_bench72_1 smartian.bench72.zip

$ poetry run aggregator generate_report_smartian sbes_bench72_2 smartian.bench72.zip

$ poetry run aggregator generate_report_smartian sbes_bench72_3 smartian.bench72.zip

$ poetry run aggregator generate_report_smartian sbes_bench72_4 smartian.bench72.zip

$ poetry run aggregator generate_report_smartian sbes_bench72_5 smartian.bench72.zip
```

## RQ1: How does the DogeFuzz bug-finding effectiveness compare to state-of-the-art fuzzers for Ethereum?

To generate the coverage graph:

```
$ mkdir cov_dogefuzz

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" blackbox > cov_dogefuzz/Dogefuzz-B.firebrick

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" greybox > cov_dogefuzz/Dogefuzz-G.slateblue

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" directed_greybox > cov_dogefuzz/Dogefuzz-DG.seagreen

$ poetry run aggregator plot_smartian_b2_instruction_coverage cov_dogefuzz

$ rm -fR cov_dogefuzz
```

To generate the bugs graph:

```
$ mkdir bug_dogefuzz

$ poetry run aggregator count_smartian_b2_bugs_found_avg "results/sbes_bench72_*" blackbox > bug_dogefuzz/Dogefuzz-B.firebrick

$ poetry run aggregator count_smartian_b2_bugs_found_avg "results/sbes_bench72_*" greybox > bug_dogefuzz/Dogefuzz-G.slateblue

$ poetry run aggregator count_smartian_b2_bugs_found_avg "results/sbes_bench72_*" directed_greybox > bug_dogefuzz/Dogefuzz-DG.seagreen

$ poetry run aggregator plot_smartian_b2_bugs_found bug_dogefuzz

$ rm -fR bug_dogefuzz
```

To generate the instruction coverage graph:

```
$ mkdir cov_tools

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" blackbox > cov_tools/Dogefuzz-B.firebrick

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" greybox > cov_tools/Dogefuzz-G.slateblue

$ poetry run aggregator count_smartian_b2_instruction_coverage_avg  "results/sbes_bench72_*" directed_greybox > cov_tools/Dogefuzz-DG.seagreen

$ python3 ../Smartian-Artifact/scripts/plot_cov.py ./results/smartian_output_5_run/output/result-B2-compare/sFuzz/* > cov_tools/sFuzz.purple

$ python3 ../Smartian-Artifact/scripts/plot_cov.py ./results/smartian_output_5_run/output/result-B2-compare/ilf/* > cov_tools/ILF.lightcoral

$ python3 ../Smartian-Artifact/scripts/plot_cov.py ./results/smartian_output_5_run/output/result-B2-compare/smartian/* > cov_tools/Smartian.darkgoldenrod

$ poetry run aggregator plot_smartian_b2_instruction_coverage cov_tools

$ rm -fR cov_tools
```

To generate the bug detection graph:

```
$ mkdir bugs_tools

$ poetry run aggregator count_smartian_b2_bugs_found_avg  "results/sbes_bench72_*" blackbox > bugs_tools/Dogefuzz-B.firebrick

$ poetry run aggregator count_smartian_b2_bugs_found_avg  "results/sbes_bench72_*" greybox > bugs_tools/Dogefuzz-G.slateblue

$ poetry run aggregator count_smartian_b2_bugs_found_avg  "results/sbes_bench72_*" directed_greybox > bugs_tools/Dogefuzz-DG.seagreen

$ python3 ../Smartian-Artifact/scripts/plot_b2_bug.py ./results/smartian_output_5_run/output/result-B2-compare/sFuzz/* > bugs_tools/sFuzz.purple

$ python3 ../Smartian-Artifact/scripts/plot_b2_bug.py ./results/smartian_output_5_run/output/result-B2-compare/ilf/* > bugs_tools/ILF.lightcoral

$ python3 ../Smartian-Artifact/scripts/plot_b2_bug.py ./results/smartian_output_5_run/output/result-B2-compare/smartian/* > bugs_tools/Smartian.darkgoldenrod

$ poetry run aggregator plot_smartian_b2_bugs_found bugs_tools

$ rm -fR bugs_tools
```

To generate the accuracy table data:

```
$ poetry run aggregator smartian_b2_alarms_avg "./results/sbes_bench72_*" blackbox

$ poetry run aggregator smartian_b2_alarms_avg "./results/sbes_bench72_*" greybox

$ poetry run aggregator smartian_b2_alarms_avg "./results/sbes_bench72_*" directed_greybox

$ python3 ../Smartian-Artifact/scripts/count_b2_alarm.py ./results/smartian_output_5_run/output/result-B2-compare/sFuzz/*

$ python3 ../Smartian-Artifact/scripts/count_b2_alarm.py ./results/smartian_output_5_run/output/result-B2-compare/ilf/*

$ python3 ../Smartian-Artifact/scripts/count_b2_alarm.py ./results/smartian_output_5_run/output/result-B2-compare/smartian/*

```

## RQ3: How efficient is DogeFuzz in fuzzing large-scale, real-world Ethereum smart contracts?

To generate the coverage boxplot graph:

```
$ cd dogefuzz-results

$ poetry run aggregator generate_report_not_labeled sbes_bench500 smartian.bench500.zip

$ poetry run aggregator plot_max_coverage_boxplot sbes_bench500 smartian.bench500.zip
```
