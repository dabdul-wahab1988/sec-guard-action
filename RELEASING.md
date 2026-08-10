# Releasing

Release only from a reviewed commit on `main` after the complete CI workflow is green.

1. Merge the release pull request into `main`.
2. Create a GitHub release tagged `v1.0.0` on that merged commit.
3. Move the supported major tag `v1` to the exact same reviewed commit.
4. Verify both refs before publishing usage examples:

   ```text
   git ls-remote --tags origin refs/tags/v1 refs/tags/v1.0.0
   ```

The `v1` tag is intentionally not created from an unmerged feature branch. Users who require immutable references should use the reviewed release commit SHA.
