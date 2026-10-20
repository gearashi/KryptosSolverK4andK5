"""Integer-only enclosures for log2 of positive integer score factors.

No floating logarithm enters the certificate. Repeated squaring works in an
outward-rounded fixed-point interval. An undecidable digit widens the returned
interval rather than guessing. Summed intervals safely filter exact products.
"""
from functools import lru_cache

FRACTIONAL_BITS = 32


@lru_cache(maxsize=8192)
def log2_interval(value, fractional_bits=FRACTIONAL_BITS, precision_bits=96):
    """Return L,U with L <= 2**fractional_bits * log2(value) <= U.

    Write value=2**k*x, 1<=x<2. At each step square the current interval;
    if wholly below2, append binary digit0; if wholly at least2, append1
    and divide by2. Every multiplication/division rounds outward. If a
    digit cannot be certified, the remaining suffix is enclosed by [0,1].
    """
    if type(value) is not int or value < 1 or value.bit_length() > 20000:
        raise ValueError("score factor must be a positive integer of at most20000bits")
    if type(fractional_bits) is not int or not 0 <= fractional_bits <= 40:
        raise ValueError("fractional_bits must be in0..40")
    if type(precision_bits) is not int or not 8 <= precision_bits <= 512:
        raise ValueError("precision_bits must be in8..512")
    exponent = value.bit_length()-1
    whole = exponent << fractional_bits
    if value == 1 << exponent:
        return whole, whole
    scale = 1 << precision_bits
    numerator = value << precision_bits
    denominator = 1 << exponent
    low = numerator // denominator
    high = (numerator+denominator-1) // denominator
    prefix = 0
    for digit in range(fractional_bits):
        low = low*low // scale
        high = (high*high+scale-1) // scale
        if high < 2*scale:
            bit = 0
        elif low >= 2*scale:
            bit = 1
            low //= 2
            high = (high+1)//2
        else:
            remaining = fractional_bits-digit
            return whole+(prefix << remaining), whole+((prefix+1) << remaining)
        prefix = 2*prefix+bit
    return whole+prefix, whole+prefix+1


def overlapping_indices(lowers, uppers, top):
    """Keep every possible top-k product, including all cutoff ties."""
    if len(lowers) != len(uppers) or not lowers:
        raise ValueError("nonempty equal-length score intervals required")
    if type(top) is not int or not 1 <= top <= len(lowers):
        raise ValueError("top must fit the page")
    if any(type(a) is not int or type(b) is not int or not 0 <= a <= b for a,b in zip(lowers,uppers)):
        raise ValueError("invalid nonnegative score interval")
    threshold = sorted(lowers, reverse=True)[top-1]
    return [i for i,upper in enumerate(uppers) if upper >= threshold], threshold
