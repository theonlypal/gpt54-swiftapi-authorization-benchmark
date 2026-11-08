# Release qualification

Version 1.0.1 corrects post-collection qualification metadata. No primary
request, response, action, execution receipt, state readback, frozen scoring
code, protocol or hypothesis is changed. No API generation was repeated.

Both offline evidence verifiers passed on the fresh public clone at
5aae1428f3c74eae9e270e4a15af649d66a12ff2 with API credentials removed.

A development-test rerun using the original checkout's external virtual
environment yielded 95 passes and 13 failures. The sandbox correctly denied
access to that environment's pyvenv.cfg outside the fresh clone's allowed
code tree. The child reported init_import_site failure and PermissionError;
the interrupted-execution fixture subsequently timed out because no client
request reached its broker. This was a replication-environment qualification
failure, not a primary effect or model-inference outcome.

The v1.0.0 tag's fresh-public-clone.json incorrectly reported the shared-
environment development test run as passing. That metadata is corrected here;
the tag is retained and is not retargeted. The completed public GitHub release
is v1.0.1.

Installing the pinned dependencies in a virtual environment inside the fresh
clone, as REPRODUCE.md specifies, yielded 108 passes, zero failures and zero
errors. The complete JUnit report is verification/fresh-clone-own-venv-tests.xml.
The ordinary record-replay verifiers do not invoke sandbox-exec and passed
under both dependency arrangements. No primary trial is excluded or modified.
