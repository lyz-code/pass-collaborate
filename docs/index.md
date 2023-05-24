[![Actions Status](https://github.com/lyz-code/pass-collaborate/workflows/Tests/badge.svg)](https://github.com/lyz-code/pass-collaborate/actions)
[![Actions Status](https://github.com/lyz-code/pass-collaborate/workflows/Build/badge.svg)](https://github.com/lyz-code/pass-collaborate/actions)

A `pass` extension that helps collectives manage the access to their passwords.

It allows you to choose which users or groups have access to the different parts of your password store in a more pleasant way than editing the `.gpg-id` files manually by making easy to:

* Create new users and groups.
* Granting or removing permissions of users or groups to parts of your store.
* Checking which passwords does a user or group have access to.

# Installing

```bash
pip install pass-collaborate
pass_collaborate init
```

# Usage

## User management

To add a new user you can run:

```bash
pass user add user_identifier
```

Where `user_identifier` can be it's name, email or GPG key. `pass_collaborate` will check your GPG key store for keys that match that identifier and will fill the required data.

If you don't like the `name` or `email` defined in the GPG key, you can override the stored values with the `--name` and `--email` flags. For example:

```bash
pass user add lyz@riseup.net --name Lyz
```

You may not need to create the users though, `pass_collaborate` tries to create them for you on the first run. You can check the existing users with `pass user list`.

If you'd like to edit any field of the users, you can open the [`.auth.yaml` file](#how-does-it-work) directly. 

## Group management

It's more convenient to manage authorisation permissions for a group of users. To create one use:

```bash
pass group add group_name user1 user2
```

Where:

* `group_name`: is a unique group name.
* `user1`, `user2`, ...: are user identifiers of already available users. It can be their names, emails or gpg keys.

Once a group is created, you can add new users with:

```bash
pass group add-users user3 user4 group_name
```

Or remove them with:

```bash
pass group remove-users user3 user4 group_name
```

Every time you change the users of a group, `pass_collaborate` will reencrypt the passwords associated to that group with the new user list.

To list the available groups run:

```bash
pass group list
```

And to get the information of a group use:

```bash
pass group show group_name
```

## Authorisation 

To grant access to a group to the directories of your password store you can use:

```bash
pass group authorize group_name pass/path/1 pass/path/2
```

If it's the first time you `authorize` a password path, `pass_collaborate` will grant access to the `group_name` members in addition to the people that already had access to that path. For example, imagine we start with a password store that has a `.gpg-id` file at the top that grants access to `admin@example.org` to all the passwords stored. When we run `pass group authorize developers web`, `pass_collaborate` will create a new `.gpg-id` file on the `web` directory granting access both to `admin` and to the members of the `developers` group. This is done this way to prevent you from locking yourself out unintentionally. If you only want `developers` to have access to the directory (not `admin` or any of the keys defined in the parent directories), you can use the `--ignore-parent` flag. For example:

```bash
pass group authorize --ignore-parent developers web
```

To remove access to a group to the directories of your password store you can use:

```bash
pass group revoke group_name pass/path/1 pass/path/2
```

## Check access

As your password store begins to grow or you start refining the permissions of the different groups and users it may be easy to get lost on who has access to what. You can check what passwords does a group or user have access with:

```bash
pass access identifier
```

Where `identifier` can be a user name, email, gpg key or group name.

# How does it work

`pass_collaborate` interacts with your password store to make the required changes in order to fulfill the desired task. To be able to do it it uses the information of:

* Your GPG key store.
* The information stored in your `pass` store (password files and `.gpg-id` files).

To store the data that is not available in the above storages, `pass_collaborate` uses an `.auth.yaml` file that is stored by default in `~/.password-store/.auth.yaml`. You can override this path with the environment variable `PASSWORD_AUTH_DIR` or the `--auth-dir` command line flag.

This is useful if the shared password store is a subdirectory of your main password store.

# References

As most open sourced programs, `pass-collaborate` is standing on the shoulders of
giants, namely:

[Pytest](https://docs.pytest.org/en/latest)
: Testing framework, enhanced by the awesome
    [pytest-cases](https://smarie.github.io/python-pytest-cases/) library that made
    the parametrization of the tests a lovely experience.

[Mypy](https://mypy.readthedocs.io/en/stable/)
: Python static type checker.

[Flakeheaven](https://github.com/flakeheaven/flakeheaven)
: Python linter with [lots of
    checks](https://lyz-code.github.io/blue-book/devops/flakeheaven#plugins).

[Black](https://black.readthedocs.io/en/stable/)
: Python formatter to keep a nice style without effort.

[Autoimport](https://lyz-code.github.io/autoimport)
: Python formatter to automatically fix wrong import statements.

[isort](https://github.com/timothycrosley/isort)
: Python formatter to order the import statements.

[PDM](https://pdm.fming.dev/)
: Command line tool to manage the dependencies.

[Mkdocs](https://www.mkdocs.org/)
: To build this documentation site, with the
[Material theme](https://squidfunk.github.io/mkdocs-material).

[Safety](https://github.com/pyupio/safety)
: To check the installed dependencies for known security vulnerabilities.

[Bandit](https://bandit.readthedocs.io/en/latest/)
: To finds common security issues in Python code.

[Yamlfix](https://github.com/lyz-code/yamlfix)
: YAML fixer.

# Contributing

For guidance on setting up a development environment, and how to make
a contribution to *pass-collaborate*, see [Contributing to
pass-collaborate](https://lyz-code.github.io/pass-collaborate/contributing).

## Donations

<a href="https://liberapay.com/Lyz/donate"><img alt="Donate using
Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a>
or
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/T6T3GP0V8)

If you are using some of my open-source tools, have enjoyed them, and want to
say "thanks", this is a very strong way to do it.

If your product/company depends on these tools, you can sponsor me to ensure I
keep happily maintaining them.

If these tools are helping you save money, time, effort, or frustrations; or
they are helping you make money, be more productive, efficient, secure, enjoy a
bit more your work, or get your product ready faster, this is a great way to
show your appreciation. Thanks for that!

And by sponsoring me, you are helping make these tools, that already help you,
sustainable and healthy.

