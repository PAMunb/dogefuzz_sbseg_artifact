# Results Aggregator

This project will aggregate the result from [benchmark](https://github.com/dogefuzz/benchmark) project.

## Running the project locally

This project using Python 3.10 and [Poetry](https://python-poetry.org/) to manage its dependencies and virtual environment.

First, install all dependdencies:

```
poetry install
```

To run the report generator, execute the following commands:

```
poetry run aggregator generate_report <experiment_folder>
```

It will look for a `experiment_folder` folder inside `/results` folder.
