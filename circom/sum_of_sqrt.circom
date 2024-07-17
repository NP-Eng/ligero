
/* The prover claims the output y is the sum of a square root of 5 and a square root of 7 */

template SumOfSqrt() {

    signal input s1;
    signal input s2;
    signal output y;

    s1 * s1 === 5;
    s2 * s2 === 7;

    y <== s1 + s2;
}

component main = SumOfSqrt();
