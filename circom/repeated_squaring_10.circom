/* Repeated squaring of x to get y */

template RepeatedSquaring() {

    signal input x;
    signal output y;

    /// repeated squaring of x to get y
    signal tmp0;
    signal tmp1;
    signal tmp2;
    signal tmp3;
    signal tmp4;
    signal tmp5;
    signal tmp6;
    signal tmp7;
    signal tmp8;
    signal tmp9;
    tmp0 <== x * x;
    tmp1 <== tmp0 * tmp0;
    tmp2 <== tmp1 * tmp1;
    tmp3 <== tmp2 * tmp2;
    tmp4 <== tmp3 * tmp3;
    tmp5 <== tmp4 * tmp4;
    tmp6 <== tmp5 * tmp5;
    tmp7 <== tmp6 * tmp6;
    tmp8 <== tmp7 * tmp7;
    tmp9 <== tmp8 * tmp8;
    y <== tmp9;
}

component main = RepeatedSquaring();
