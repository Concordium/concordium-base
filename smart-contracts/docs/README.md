# Concordium Smart Contract Developer Documentation

The documentation is structured according to this
[guide](https://documentation.divio.com/), and the command-line syntax is
documented according to [Google's guide on the topic](https://developers.google.com/style/code-syntax).

The documentation is written in reStructuredText ([Link to the basics](https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html)).

For building the documentation we use [Sphinx](https://www.sphinx-doc.org/en/master/index.html) and the [theme from ReadTheDocs](https://sphinx-rtd-theme.readthedocs.io/en/stable/) with minor design tweaks.

Sphinx supplies a number of useful ["directives"](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html) (The sphinx equivalent of LaTeX commands) for stuff like code highlighting, remarks, warnings and so on.

Additionally we have enabled the [extension for todo](https://www.sphinx-doc.org/en/master/usage/extensions/todo.html) directive:
```
.. todo::
    Write the todo here
```
Todos are shown as warnings when building the docs.

To generate SVG graphics, we use the [Graphviz extension](https://www.sphinx-doc.org/en/master/usage/extensions/graphviz.html).

## Installation

Install `python3` and the python package manager `pip`.

To install the python dependencies run:
```
pip install -r requirements.txt
```

Install `graphviz`:

- MacOS: `brew install graphviz`
- Ubuntu: `sudo apt install graphviz`

## Development
To watch the doc files and automate the build run:
```
make dev
```
and navigate to [localhost:8000](http://localhost:8000).

Before committing make sure to run the linter and fix all the errors reported:
```
make lint
```

> **Note**: In `make dev` we disable the cache on build as this tends to cause inconsistencies.
> If the build time becomes too slow, it might be worth enabling again by removing `-E`.

## Build the docs
Run the following command:
```
make html
```


To check for dead links (also done by the CI), run:
```
make linkcheck
```


## Gitlab Pages

The documentation can be release on Gitlab pages by triggering a manual CI job called `pages`.
The build can be reached at https://concordium.gitlab.io/smart-contracts/
but only by people with access to this repository.

This is useful for sharing drafts of the documentation without having people
setting up a build step.


## Style guide

### Headers
Use *sentence-style capitalization*, i.e., only capitalize the first letter of a
header.

Be consistent in the use of characters for creating headers; use the following
for each level of header:

``` restructuredtext
========
Header 1
========

Header 2
========

Header 3
--------

Header 4
^^^^^^^^

Header 5
~~~~~~~~
```

### Terminal commands

Use `code-block:: console` to show content from a terminal and prepend commands
with `$` without a space in between.

A space is added between `$` and the command through CSS.
This solution makes only the command itself copyable, thereby improving the user-experience.

Example:

``` restructuredtext
.. code-block:: console

   $echo Hello, world!
   Hello, world!
```

### Indentation
Use three spaces for indentation.
This aligns the directive name (`note::`) with the content of the directive (`This line...`).

Add an empty line between a directive and its content.

Example that follows both rules:

``` restructuredtext
.. note::

   This line has three spaces in front of it and it has an empty line above it.
```
