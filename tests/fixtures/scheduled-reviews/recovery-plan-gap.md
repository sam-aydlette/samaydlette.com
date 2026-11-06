# Recovery plan (known-bad fixture)

The tabletop must fail: one scenario has no stated recovery, and there is no
Recovery procedure section.

In-scope loss scenarios:
- Site content deleted — restore from the deployed commit
- State table lost — point-in-time recovery
- The intern unplugs the cloud
