# Security policy

## Supported versions

rdnie is pre-1.0: only the latest release gets fixes.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/sgomez/rdnie/security/advisories/new). Do not open a public issue.

Include the affected version, the platform, and the steps or APDU exchange that reproduce it. Leave out anything that identifies a card holder: certificates, names, document or serial numbers, and APDU dumps containing them.

You will get an answer within 7 days. Once a fix ships, the advisory is published with credit to the reporter, unless they prefer otherwise.

## Scope

In scope: the secure channel, PIN handling, signing, and any path that leaks card or PIN data. Bugs in JMulticard itself go to [its maintainers](https://github.com/ctt-gob-es/jmulticard).
