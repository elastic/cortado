# Contributing to Cortado

Thank you for your interest in contributing to Cortado. We've crafted this document to make it simple and easy for you
to contribute. We recommend that you read these contribution guidelines carefully so that you spend less time working on
GitHub issues and PRs and can be more productive contributing to this repository.

If you want to be rewarded for your contributions, sign up for the [Elastic Contributor
Program](https://www.elastic.co/community/contributor). Each time you make a valid contribution, you'll earn points that
increase your chances of winning prizes and being recognized as a top contributor.

These guidelines will also help you post meaningful issues that will be more easily understood, considered, and
resolved. These guidelines are here to help you whether you are opening an issue or requesting a feature.

## Table of Contents

- [Contributing to Cortado](#contributing-to-cortado)
  - [Table of Contents](#table-of-contents)
  - [Effective issue creation in Cortado](#effective-issue-creation-in-cortado)
    - [Why we create issues before contributing code](#why-we-create-issues-before-contributing-code)
    - [What a good issue looks like](#what-a-good-issue-looks-like)
    - ["My issue isn't getting enough attention"](#my-issue-isnt-getting-enough-attention)
    - ["I want to help!"](#i-want-to-help)
  - [Development workflow](#development-workflow)
    - [Forking and setup](#forking-and-setup)
    - [Commit messages](#commit-messages)
    - [Creating a pull request](#creating-a-pull-request)
    - [Code review](#code-review)
  - [Signing the contributor license agreement](#signing-the-contributor-license-agreement)

## Effective issue creation in Cortado

### Why we create issues before contributing code

Before contributing code, we recommend starting by creating a GitHub issue. This allows us to discuss ideas and gather
feedback early in the process, fostering collaboration and making sure we're aligned on feasibility and implementation
approaches. By front-loading the conversation, we can work together to refine the concept before moving forward with a
pull request.

By contrast, starting with a pull request makes it more difficult to revisit the approach. Many PRs are treated as
mostly done and shouldn't need much work to get merged. Nobody wants to receive PR feedback that says "start over" or
"closing: won't merge." That's discouraging to everyone, and we can avoid those situations if we have the discussion
together earlier in the development process. It might be a mental switch for you to start the discussion earlier, but it
makes us all more productive and our code easier to maintain.

### What a good issue looks like

We have a few types of issue templates to [choose from](https://github.com/elastic/cortado/issues/new/choose). If you
don't find a template that matches or simply want to ask a question, create a blank issue and add the appropriate
labels.

* **General Bug Report**: report a bug in Cortado codebase.
* **RTA Bug Report**: report a bug in Cortado RTA code
* **Feature Request**: suggest an idea for Cortado

### "My issue isn't getting enough attention"

First of all, **sorry about that!** We want you to have a great time with Cortado.

We'll tag issues and pull requests with the target release if applicable. With all of the issues, we need to prioritize
according to impact and difficulty, so some issues can be neglected while we work on more pressing issues.

Of course, feel free to bump your issues if you think they've been neglected for a prolonged period.

Issues and pull requests will be marked as `stale` after 60 days of inactivity. After 7 more days of incactivity, they
will be closed automatically.

If an issue or pull request is marked `stale` and/or closed, this does not mean it's not important, just that there may
be more work than available resources over a given time. We feel that it's a better experience to generate activity
responding to a stale issue or letting it close, than to let something remain open and neglected for longer periods of
time.

If your issue or pull request is closed from inactivity and you feel this is an error, please feel free to re-open it
with comments and we will try our best to respond with justification to close or to get it the proper attention.

### "I want to help!"

If you have identified a bug or a feature you would like to implement for Cortado, please start by searching for an
existing issue related to it on GitHub. If no issue exists, open a new one to describe your planned contribution.
Clearly outline the problem, your proposed solution, and any relevant details. This step is important because:

- Someone else may already be working on the same issue.
- There might be existing considerations or constraints that could impact your implementation.

By discussing your idea beforehand, we can avoid duplicated efforts and provide guidance to help you get started
effectively.

## Development workflow

This section outlines the process and best practices for contributing to the project, from setting up your fork to
merging your changes. By following these guidelines, you can help maintain a clear and consistent development workflow.

### Forking and setup

We use the [GitHub forking model](https://help.github.com/articles/fork-a-repo/) for collaboration. To get started:

1. Fork the repository to your GitHub account.
2. Clone your fork locally and add the official repository as a remote called `upstream`:
   ```bash
   git remote add upstream https://github.com/elastic/cortado.git
   ```

This setup ensures you can pull the latest changes from the official repository and keep your fork up to date.

### Commit messages

Since the repository enforces squash-and-merge, the pull request title is what matters for the main branch. However,
commit messages within the pull request can still be helpful during the review process. Feel free to make as many
commits as needed while developing, and use clear and descriptive messages to document your changes.
- `feat: add support for multi-region deployment`

### Creating a pull request

A pull request should clearly communicate the intent and details of your changes. Here's what to include:

- PR title: the pull request title will become the final commit message in the main branch. It must follow the
  [Conventional Commits](https://www.conventionalcommits.org) specification. Use a type prefix (e.g., `feat:`, `fix:`,
  `chore:`) and provide a concise summary of the changes. For example:
  - `fix: correct typo in the error message`
  - `feat: add support for the latest version of macOS`
- PR Description: include a clear explanation of your changes. Explain the problem you are solving, how your solution
  works, and why the changes are necessary.
- References: add links to relevant issues, external resources, or related pull requests to provide context.

#### Submitting a pull request

1. Push your local changes to your forked copy of the repository.
2. Open a pull request against the `main` branch.
3. In your PR description:
 - Clearly explain the purpose of your changes and how they address the issue or add value.
 - Reference the issue where prior discussion took place by mentioning it, e.g., `Closes #123`.

Adhering to these guidelines ensures your contribution is easy to review, and the repository's history remains clear and
consistent.

### Code review

Once your pull request is submitted:
- Be prepared to participate in a discussion. We may provide feedback or request changes to ensure your contribution
  aligns with the project's goals and standards.
- Remember, our goal is to collaborate with you to integrate your contributions effectively into the project.

We appreciate your effort and look forward to reviewing your work!

## Signing the contributor license agreement

Please make sure you've signed the [Contributor License Agreement](http://www.elastic.co/contributor-agreement/). We're
not asking you to assign copyright to us, but to give us the right to distribute your code without restriction. We ask
this of all contributors in order to assure our users of the origin and continuing existence of the code. You only need
to sign the CLA once.

