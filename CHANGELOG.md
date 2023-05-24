## 0.1.2 (2023-05-24)

### Fix

- correct location of assets

## 0.1.1 (2023-05-24)

### Fix

- configure pass extension with pass_collaborate init

## 0.1.0 (2023-03-15)

### Feat

- add the revoke functionality
- add --ignore-parent to authorize command
- automatically import the available gpg keys to the auth store
- build the package to be an extension of pass
- add the access report for user and groups
- allow users to be added or removed from groups
- authorize or revoke permissions to a path to a group
- add users to a group reencrypts the pass store
- authorize a user or group to a directory
- initial iteration

### Fix

- correct ruyaml version
- drop support for python < 3.9
- add more information when reencrypting fails
- prevent reencrypting from introducing encrypted data in encrypted file
- load gpg keys even if access element exists
- avoid duplicate information in the access store when authorizing new users
- make the authorize command idempotent
- store the emails when creating a group despite the used identifiers
- autoload add user information from gpg key store

### Refactor

- auth and pass_
- create PassStore as unique entrypoint

### Perf

- improve access speed
