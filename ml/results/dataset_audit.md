# Dataset audit (heuristic checks, not ground truth)

Flags are simple text rules. minified: a line over 400 characters, or one line over 300 characters. wrong_language: code starts like another language. fragment: Python not starting with def, async def, class or a decorator; JavaScript starting with a closing bracket, comma, dot or backtick. suspect: any of the three.

| split | language | rows | minified | wrong language | fragment | suspect | vulnerable rate in suspect rows | vulnerable rate in other rows |
|---|---|---|---|---|---|---|---|---|
| train | python | 5894 | 0.2% | 0.2% | 0.5% | 0.7% (43) | 30.2% | 35.2% |
| train | javascript | 36162 | 80.9% | 0.0% | 1.0% | 81.3% (29396) | 48.1% | 32.9% |
| test | python | 1066 | 0.5% | 0.0% | 0.0% | 0.5% (5) | 40.0% | 38.9% |
| test | javascript | 2570 | 17.0% | 0.3% | 2.0% | 18.5% (476) | 45.4% | 44.1% |

## Before-fix vs after-fix pairs: is the vulnerable version shorter

| split | pairs | vulnerable shorter than fixed | same length |
|---|---|---|---|
| train | 11411 | 28.9% | 55.3% |
| test | 1272 | 78.0% | 10.0% |