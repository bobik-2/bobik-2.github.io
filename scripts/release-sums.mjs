// Sumy src/ z `git archive <ref>` w formacie releases/<X.Y.Z>.sha256.
// Użycie: node scripts/release-sums.mjs [<ref>=HEAD] > releases/<X.Y.Z>.sha256
import { sumsAt } from "./release-lib.mjs";

process.stdout.write(await sumsAt(process.argv[2] ?? "HEAD"));
