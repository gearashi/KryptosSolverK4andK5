# Mixed-alphabet constraint audit — checkpoint F

This is an independent derivation for two additive substitutions using possibly different alphabet orders, with one explicit transposition. It does not assume that either alphabet or transposition was historically used for K4. Engine files were not read or changed for this derivation. All positions below are zero-based.

## Model and the three placements

Let A and B each be permutations of the same 26 letter symbols. Write a letter's index as idxA or idxB. Substitution with alphabet A and index-valued key a is

`S_A(x,a) = A[(idxA(x)+a) mod 26]`,

and analogously for B. The order of substitutions is A then B. A gather transposition is `T(x)[j]=x[pi[j]]`, so an original plaintext position i finishes at ciphertext position `j=inverse_pi[i]`. For A-key period p and B-key period q, the relevant phases are:

| Encryption order | A-key phase u | B-key phase v |
|---|---:|---:|
| SST: A, B, T | i mod p | i mod q |
| STS: A, T, B | i mod p | j mod q |
| TSS: T, A, B | j mod p | j mod q |

The transposition changes positions, not letters. Therefore every known plaintext/ciphertext pair satisfies the same letter equation, with only its phase choices changed:

`b_v = idxB(C_j) - idxB(A[(idxA(P_i)+a_u) mod 26]) mod 26`.

This matches the proposed engine equation. Neither substituting `pi[i]` for `inverse_pi[i]` nor indexing every key by the final plaintext coordinate is generally valid.

Define the alphabet-index permutation `h(x)=idxB(A[x])`, and abbreviate `p_i=idxA(P_i)` and `c_j=idxB(C_j)`. The edge relation becomes `b_v=c_j-h(p_i+a_u)`. It is a bijection from one key variable to the other. Its inverse is

`a_u = idxA(B[(c_j-b_v) mod 26]) - p_i mod 26`.

Each operation here is invertible because the alphabets are permutations. No division modulo 26 is used.

## Why 26 root trials per component are complete

Construct a bipartite multigraph whose vertices are the p A-key phases and q B-key phases, including isolated vertices. Each crib is one edge carrying its two-way bijection.

In a connected component, choose any vertex as root and a spanning tree. For each of its 26 possible root values, tree propagation fixes every other vertex uniquely. Check every remaining edge, including parallel edges, against those values. Accept the root exactly when all equations hold.

Every solution has one definite root value and propagation reconstructs it, so no solution is missed. Two root values give different key assignments, so none are counted twice. If a component has s surviving roots, it has exactly s assignments. Components are independent, hence the total number of full key assignments is `product(s_component)`. An isolated vertex contributes 26. A component with zero survivors makes the whole model infeasible.

These counts refer to fixed-length key arrays whose periods divide the declared lengths. They do not count only primitive/minimal-period keys, nor do they deduplicate different models or different keys producing the same full plaintext.

Equivalently, each non-tree edge compares two permutations of the root value; surviving roots are their equality sets' intersection. Thus a component has between 0 and 26 solutions. A useful consistency check is that 25 cannot occur: two permutations agreeing at 25 points also agree at the last point. Any nontrivial check rejects at least two roots; intersecting checks cannot leave exactly 25.

## Forests and cycles

A tree has no non-tree edges, so all 26 root values survive, whatever the crib letters and edge labels are. A forest with c components therefore always has `26^c` key assignments. The presence of two different alphabets does not turn forest crib fits into positive consistency evidence.

The multigraph cycle rank is `E-V+c`, counting parallel crib edges and isolated vertices correctly. Cycles can remove root values, but their count alone does not determine how many survive. A cycle may impose an identity and remove none. Multiple cycle constraints may overlap. Do not infer a solution count by subtracting one degree of freedom per cycle or dividing a count by 26 per cycle.

## Plaintext uniqueness is a separate calculation

For any full-message position i and `j=inverse_pi[i]`, reconstruction is

`P_i = A[(idxA(B[(idxB(C_j)-b_v) mod 26])-a_u) mod 26]`.

If u and v belong to the same crib-graph component, evaluate this letter across that component's surviving root assignments. If they belong to different components, evaluate all pairs of surviving assignments from those two components. The other components cannot affect that position. At most 26 or 676 evaluations per position are needed.

For a feasible model, the entire plaintext is unique exactly when every position's resulting set of letters is a singleton. This criterion is necessary and sufficient: any nonsingleton letter set is realized by at least two valid global key assignments, because other components can be completed independently. A zero-solution model has no plaintext; uniqueness is not assigned vacuously.

One connected component is not enough to guarantee uniqueness when the alphabets differ. Multiple surviving roots may alter unknown plaintext letters. Conversely, multiple key assignments can still yield exactly one plaintext. Count keys and distinct plaintexts separately.

## The special gauge case

When A=B, the relation is `a_u+b_v=c_j-p_i`. In each feasible connected component, the transformation `a -> a+t`, `b -> b-t` preserves every equation, giving exactly 26 roots. The reconstructed plaintext at a position is invariant if both relevant phase vertices belong to the same component. If they belong to different components, their independent shifts can change that letter.

Thus in the shared-alphabet model, full plaintext uniqueness is equivalent to every full-message phase pair lying within one crib-graph component; the entire graph need not itself be connected. Connectivity is a sufficient shortcut in that special case.

The same conclusion holds if the index change is affine, `h(x)=s*x+t mod26`, where gcd(s,26)=1: the gauge is `a -> a+d`, `b -> b-s*d`. A genuinely non-affine index permutation need not have that symmetry. Alphabet strings differing is therefore not, by itself, proof that the gauge disappears.

## Hand vector that exposes the distinction

Use these literal alphabets and indices:

```text
A = ABCDEFGHIJKLMNOPQRSTUVWXYZ
B = BACDEFGHIJKLMNOPQRSTUVWXYZ
pi      = [0,2,3,1,5,4]
inverse = [0,3,1,2,5,4]
P = ABCDEF
a = [1,4]
b = [2,7,11]
```

B exchanges A and B and fixes the other letters. Its index change is non-affine: h(0)=1 and h(1)=0 would force slope -1 and intercept 1, which would give h(2)=25; its actual h(2) is 2. The transposition is non-involutive, so forward/inverse mistakes are observable.

Applying the stages literally gives SST=`COJMUM`, STS=`CKSHQQ`, and TSS=`CNPHNT`. In STS, the first intermediate string is `BFDHFJ`, then transposition gives `BDHFJF`, then the B substitution gives `CKSHQQ`.

For STS retain only plaintext positions 0,1,3,4,5, namely `AB?DEF`. The five phase edges are `(A0,B0)`, `(A1,B0)`, `(A1,B2)`, `(A0,B2)`, `(A1,B1)`. This is a connected five-vertex graph with one cycle. Exactly two assignments survive:

| A key | B key | Full plaintext | Reencrypted ciphertext |
|---|---|---|---|
| [1,4] | [2,7,11] | ABCDEF | CKSHQQ |
| [20,24] | [8,13,18] | ABDDEF | CKSHQQ |

This is a direct counterexample to transferring connected-implies-unique-plaintext into the general mixed-alphabet model. Restoring the sixth crib leaves exactly the first assignment. Keeping only positions 0,1,3,5 gives a spanning tree and exactly 26 assignments.

The bounded independent script `research/mixed_alphabet_hand_checks.py` enumerates all 676 A-key pairs for each of these three small STS cases, infers B phases from cribs, and directly reencrypts every retained plaintext with compositional stage functions. It imports no engine code. Results, runtime, and script hash are in `research/mixed_alphabet_hand_checks.json`. This verifies the toy counts 26, 2, 1 and the three stage-order ciphertexts; the general completeness and uniqueness arguments above are separate from that finite check.

## Review targets for implementation

Validate both alphabet strings as 26 distinct copies of the same letters; invert gather permutations explicitly; retain separate A/B vertex namespaces; include isolated key phases in assignment counts; reject a root on any contradictory edge; retain all surviving root assignments instead of only a convenient representative; and determine plaintext uniqueness by actual letter sets. Shared-alphabet or affine-gauge optimizations need their stated hypothesis checked first.
