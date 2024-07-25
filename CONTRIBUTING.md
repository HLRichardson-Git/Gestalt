# Contributing to Gestalt

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to Gestalt, which are hosted in the [Gestalt Organization](https://github.com/GestaltCrypto) on GitHub. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

#### Table Of Contents

[Code of Conduct](#code-of-conduct)

[I don't want to read this whole thing, I just have a question!!!](#i-dont-want-to-read-this-whole-thing-i-just-have-a-question)

[What should I know before I get started?](#what-should-i-know-before-i-get-started)
  * [Understanding Cryptography](#understanding-cryptography)

[How Can I Contribute?](#how-can-i-contribute)
  * [Reporting Bugs](#reporting-bugs)
  * [Suggesting Enhancements](#suggesting-enhancements)
  * [Your First Code Contribution](#your-first-code-contribution)
  * [Pull Requests](#pull-requests)

[Styleguides](#styleguides)
  * [Git Commit Messages](#git-commit-messages)
  * [Cpp Styleguide](#cpp-styleguide)
  * [Documentation Styleguide](#documentation-styleguide)

[Additional Notes](#additional-notes)
  * [Issue and Pull Request Labels](#issue-and-pull-request-labels)

## Code of Conduct

This project and everyone participating in it, is governed by the [Gestalt Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [hunter@hunterrichardson.com]().

## I don't want to read this whole thing I just have a question!!!

> **Note:** Please don't file an issue to ask a question. You'll get faster results by using the resources below.

We have an official message board with a detailed FAQ, where the community chimes in with helpful advice if you have questions.

* [Github Discussions, the official Gestalt message board](https://github.com/HLRichardson-Git/Gestalt/discussions)

## What should I know before I get started?

### Understanding Cryptography

Cryptography is a very complex field of Mathematics and is prone to errors when implemented. If you wish to contribute cryptographic functionality to Gestalt it is expected that you do your due diligence in researching the respective algorithm, its pitfalls, and other software implementations of the algorithm. Here are some resources that are commonly referenced by contributors:

* [NIST](https://csrc.nist.gov/publications/fips)
* [Understanding Cryptography](https://link.springer.com/book/10.1007/978-3-642-04101-3)
* [Applied Cryptography](https://www.schneier.com/books/applied-cryptography/)

### Design Decisions

If you have a question about how we do things, check to see if it is documented. If it is *not* documented, please open a new topic on [Github Discussions, the official Gestalt message board](https://github.com/HLRichardson-Git/Gestalt/discussions) and ask your question.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Gestalt. Following these guidelines helps maintainers and the community understand your report :pencil:, reproduce the behavior :computer: :computer:, and find related reports :mag_right:.

Before creating bug reports, please check [this list](#before-submitting-a-bug-report) as you might find out that you don't need to create one. When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report) in your issue.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

#### Before Submitting A Bug Report

* **Check the [debugging guide](https://gestaltcrypto.github.io/).** You might be able to find the cause of the problem and fix things yourself. Most importantly, check if you can reproduce the problem in the latest version of Gestalt.
* **Check the [discussions](https://github.com/HLRichardson-Git/Gestalt/discussions)** for a list of common questions and problems.
* **Perform a [cursory search](https://github.com/HLRichardson-Git/Gestalt/issues)** to see if the problem has already been reported. If it has **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://github.com/HLRichardson-Git/Gestalt/issues). After you've determined you have found a new bug, create an issue on that repository and provide the following information by filling out an issue.

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps that reproduce the problem** in as many details as possible. For example, start by explaining how you built Gestalt, e.g. your environment. When listing steps, **don't just say what you did, but explain how you did it**.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **If the problem is related to performance or memory**, include a [CPU profile capture](https://github.com/wolfpld/tracy) with your report.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened and share more information using the guidelines below.

Provide more context by answering these questions:

* **Did the problem start happening recently** (e.g. after updating to a new version of Gestalt) or was this always a problem?
* If the problem started happening recently, **can you reproduce the problem in an older version of Gestalt?** What's the most recent version in which the problem doesn't happen? You can download older versions of Gestalt from [the releases page](https://github.com/HLRichardson-Git/Gestalt/releases).
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which conditions it normally happens.

Include details about your configuration and environment:

* **Which version of Gestalt are you using?**
* **What's the name and version of the OS you're using**?

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Gestalt, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion :pencil: and find related suggestions :mag_right:.

Before creating enhancement suggestions, please check [this list](#before-submitting-an-enhancement-suggestion) as you might find out that you don't need to create one. When you are creating an enhancement suggestion, please [include as many details as possible](#how-do-i-submit-a-good-enhancement-suggestion). Fill out an issue, including the steps that you imagine you would take if the feature you're requesting existed.

#### Before Submitting An Enhancement Suggestion

* **Perform a [cursory search](https://github.com/HLRichardson-Git/Gestalt/issues)** to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://github.com/HLRichardson-Git/Gestalt/issues). After you've determined your enhancement suggestion, create an issue on that repository and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. For example, how other cryptography libraries implemented your enhancement.
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Explain why this enhancement would be useful** to most Gestalt users and isn't something that can or should be implemented by a user. For example, a proprietary key agreement scheme.
* **List some other libraries or applications where this enhancement exists.**
* **Specify which version of Gestalt you're using.**
* **Specify the name and version of the OS you're using.**

### Your First Code Contribution

Unsure where to begin contributing to Gestalt? You can start by looking through these `beginner` and `help-wanted` issues:

* [Beginner issues](https://github.com/HLRichardson-Git/Gestalt/labels/beginner) - issues that should only require a few lines of code, and a test or two.
* [Help wanted issues](https://github.com/HLRichardson-Git/Gestalt/labels/help%20wanted) - issues which should be a bit more involved than `beginner` issues.

Both issue lists are sorted by total number of comments. While not perfect, a number of comments is a reasonable proxy for the impact a given change will have.

### Pull Requests

The process described here has several goals:

- Maintain Gestalt's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible Gestalt
- Enable a sustainable system for Gestalt's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Follow the [styleguides](#styleguides)
2. After you submit your pull request, verify that all unit tests are passing

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Cpp Styleguide

* **Variables** should be camelCase
    ```cpp
    int someNumber = 0;
    ```
* **Constants** use ALL_CAPS_WITH_UNDERSCORES
    ```cpp
    const int SOME_CONSTANT_NUMBER = 0;
    ```
* **Functions** use camelCase for function names, and use verbs to describe actions.
    ```cpp
    void calculateArea();
    ```
* **Classes & Structs** use PascalCase, and private should be first.
    ```cpp
    class SomeClass {
    private:
      // private functions/ variables
    public:
      // public functions/ variables
    }
    ```
* **Indentions over spaces**
    ```cpp
    // Do:
    class ExampleClass {
    public:
        void exampleFunction() {
            int value1 = 10;
            int longValue2 = 20;
            int value3 = 30;

            if (value1 > 0) {
                doSomething(); // Proper indentation with tabs or spaces
            }
        }
    };

    // Don't:
    class SomeClass {
    public:
        void exampleFunction() {
            int value1     = 10;
            int longValue2 = 20;
            int value3     = 30;

            if (value1 > 0) {
                doSomething();    // Indentation mixed with spaces
            }
        }
    };
    ```
* **Braces** should be placed on the same line as the statement declaration, and should be used even for single-line blocks.
    ```cpp
    if (condition) {
        // code block
    } else {
        // code block
    }
    ```
* **Spacing** should be used around operators and after commas, but **not** immediately inside parenthesis, brackets, or braces.
    ```cpp
    int sum = 0;
    for (int i = 0; i < 10; ++i) {
        sum += i;
    }
    ```
* **Comments** should use `//` for a single-line comment and `/* */` for multi-line comments with a `*` on each line. Do not use comments to describe everything, if you are writing a comment first ask if you can rewrite variable names to explain an operation.
  * Single line comment:
    ```cpp
    int result = calculateSum(a, b); // Calculate the sum of a and b
    ```
  * Multi-line comment:
    ```cpp
    /*
     * This function performs a complex calculation.
     * It takes two parameters and returns their sum.
     * The calculation is optimized for performance.
     */
    int calculateSum(int a, int b) {
        return a + b;
    }
    ```
  * Descriptive variables:
    ```cpp
    // Before
    int x; // Result of the calculation

    // After
    int calculationResult;
    ```
  * Avoid redundant comments:
    ```cpp
    // Redundant comment
    int sum = a + b; // Add a and b

    // Improved code without unnecessary comment
    int sum = a + b;
    ```
  * Explain why, no what:
    ```cpp
    // Good comment explaining why
    int result = calculateSum(a, b); // Using calculateSum for precision in floating-point addition
    ```
* **Avoid magic numbers** by using named constants instead of raw literals to improve code readability.
  ```cpp
    // Do: 
    const double PI = 3.14159;
    int radius = 10;
    double area = PI * radius * radius;

    // Don't:
    int radius = 10;
    double area = 3.14159 * radius * radius; // Magic number for Pi
    ```
* **Error handling** should always be considered.
* **Use standard library** when able to, adding additional dependencies should be rare.
* **Naming** should be clear and explicit. **BUT** if you are implementing a standard algorithm, then the names of variables of the standard shall be used.

### Documentation Styleguide

* Use [Markdown](https://daringfireball.net/projects/markdown).
* Reference methods and classes in markdown with the custom `{}` notation:
    * Reference classes with `{ClassName}`
    * Reference instance methods with `{ClassName::methodName}`
    * Reference class methods with `{ClassName.methodName}`

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help us track and manage issues and pull requests.

The labels are loosely grouped by their purpose, but it's not required that every issue has a label from every group or that an issue can't have more than one label from the same group.

Please open an issue on `Gestalt` if you have suggestions for new labels.

#### Type of Issue and Issue State

| Label name | Description |
| --- | --- |
| `enhancement`  | Feature requests. |
| `bug`  | Confirmed bugs or reports that are very likely to be bugs. |
| `question`  | Questions more than bug reports or feature requests (e.g. how do I do X). |
| `feedback`  | General feedback more than bug reports or feature requests. |
| `help-wanted`  | The Gestalt core team would appreciate help from the community in resolving these issues. |
| `beginner`  | Less complex issues which would be good first issues to work on for users who want to contribute to Gestalt. |
| `more-information-needed`  | More information needs to be collected about these problems or feature requests (e.g. steps to reproduce). |
| `needs-reproduction`  | Likely bugs, but haven't been reliably reproduced. |
| `blocked`  | Issues blocked on other issues. |
| `duplicate` | Issues which are duplicates of other issues, i.e. they have been reported before. |
| `wontfix`  | The Gestalt core team has decided not to fix these issues for now, either because they're working as intended or for some other reason. |
| `invalid` | Issues which aren't valid (e.g. user errors). |