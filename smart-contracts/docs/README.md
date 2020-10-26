# Concordium Smart Contract Developer Documentation

The documentation is written in reStructuredText ([Link to the basics](https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html)).

For building the documentation we use [Sphinx](https://www.sphinx-doc.org/en/master/index.html) and the theme from ReadTheDocs with minor design tweaks.

Sphinx supplies a number of useful ["directives"](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html) (The sphinx equivalent of LaTeX commands) for stuff like code highlighting, remarks, warnings and so on.

Additionally we have enabled the [extension for todo](https://www.sphinx-doc.org/en/master/usage/extensions/todo.html) directives
```
.. todo::
    Write the todo here
```



## Installation

Install `python3` and the python package manager `pip`.

To install the python dependencies run
```
pip install -r requirements.txt
```

## Development
To watch the doc files and automate the build run:

On Linux
```
make dev
```
and navigate to [localhost:8000](http://localhost:8000)

> **Note**: In `make dev` we disable the cache on build as this tend to inconsistencies.
> If the build time gets to slow, it might be worth enabling again by removing `-E`.

## Build the docs

On Linux
```
make html
```


To check for deadlinks (also done by the CI)
```
make linkcheck
```
