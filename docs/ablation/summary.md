# Grounding ablation summary

Snippets tried: 33. Used: 31. Excluded: 2.
- excluded py-auth-decode-no-key: detectors did not flag the intended class
- excluded js-secret-password-config: detectors did not flag the intended class

| Measure | Grounded | Free-form |
|---|---|---|
| Usable replies | 30/31 | 31/31 |
| Good fix (of usable replies) | 25/30 = 83% (95% CI 66-93%) | 26/31 = 84% (95% CI 67-93%) |
| Target class gone | 28/30 = 93% (95% CI 79-98%) | 29/31 = 94% (95% CI 79-98%) |
| Fix introduces a new class | 3 | 3 |
| Fix does not parse | 0 | 0 |

Paired comparison on 30 snippets where both arms gave a usable reply:
- good fix only with grounding: 2; only without grounding: 2
- exact McNemar p-value (two-sided): 1.000

By source and class (good fix, grounded vs free-form, usable replies only):

- class=broken_authentication: grounded 3/4, free-form 3/4
- class=hardcoded_secret: grounded 8/8, free-form 8/8
- class=sql_injection: grounded 8/8, free-form 9/9
- class=xss: grounded 6/10, free-form 6/10
- language=javascript: grounded 13/14, free-form 13/14
- language=python: grounded 12/16, free-form 13/17
- source=exercise: grounded 10/11, free-form 9/11
- source=new: grounded 15/19, free-form 17/20

Limits: small corpus; snippets were kept only if the detectors flag them; 'good fix' means
the detectors no longer flag the target class, not that the code is proven secure; one run,
temperature 0, one model. Human ratings (ratings_blind.csv) are a separate measure.