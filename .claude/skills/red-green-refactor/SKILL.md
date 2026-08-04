---
name: red-green-refactor
description: Test-driven development discipline for implementing a change. Use whenever writing or modifying application logic, implementing an issue, or when the user asks for TDD. Enforces writing one failing test first, confirming it fails, then making it pass.
---

# Red, green, refactor

Write the test first. Not "write tests for this" — write **one** failing test,
watch it fail, then make it pass.

This is not a style preference. When you write the implementation first and the
tests afterwards, you write tests that describe what the code does rather than what
it should do, and they pass whether or not the code is correct.

## The cycle

### Red

1. Pick the **smallest** behaviour not yet covered. One assertion's worth.
2. Write the test. Give it a name that states the behaviour, not the method
   (`awards 10 points on first lesson completion`, not `testAwardPoints`).
3. **Run it.** Report the failure output.
4. Confirm it fails **for the right reason** — module not found, or a real assertion
   mismatch. If it fails on a typo, a bad import, or a missing fixture, that is not
   red; fix the test and run it again.

Never skip step 3. A test you haven't watched fail is not a test.

### Green

5. Write the **minimum** implementation that passes. Not the general case, not the
   next three behaviours you can see coming.
6. Run it. Report the pass.

### Refactor

7. Clean up with the test still green. Run again.

Then loop back to red for the next behaviour.

## Rules

- **One failing test at a time.** Do not write five tests then implement.
- **Never weaken a test to make it pass.** If a test is failing and you're editing
  the test, stop and say so explicitly. This includes loosening an assertion,
  widening a tolerance, adding a skip, or regenerating a snapshot.
- **Never assert on a mock.** If the test only proves you called a mock, it proves
  nothing. Test at the module's public interface against a real (in-memory)
  dependency.
- **Test at the deep seam.** Draw the boundary around the whole module and test
  through its public interface. Do not wrap each internal function in its own test —
  that produces a brittle suite that verifies structure rather than behaviour.
- If a behaviour genuinely cannot be tested, say so and say why. Do not write a
  hollow test to fill the gap.

## Finishing

Run the full feedback loop from `CLAUDE.md` — test, typecheck, lint — and report
each result. Fix what you broke. Do not report success on a partial pass.
