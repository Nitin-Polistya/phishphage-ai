# License audit

## Result

No root `LICENSE`, `LICENSE.md`, or equivalent project license file was found in the tracked repository. A license decision is required before the project is redistributed as a licensed work.

No license was selected or added automatically.

## Related observations

- Dataset licenses and source restrictions are documented separately in [docs/DATASETS.md](../../docs/DATASETS.md) and the ML source registries.
- A source being public does not grant permission to train on, retain, or redistribute raw email.
- Dependency license files under local virtual environments and `node_modules` are third-party package metadata, not a root project license.
- Private model artifacts and raw datasets are ignored by Git and are not treated as public project assets.
