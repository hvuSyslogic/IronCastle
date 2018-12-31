using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;
using Arrays = org.bouncycastle.util.Arrays;

namespace org.bouncycastle.math.ec
{
		
	public abstract class ECFieldElement : ECConstants
	{
		public abstract BigInteger toBigInteger();
		public abstract string getFieldName();
		public abstract int getFieldSize();
		public abstract ECFieldElement add(ECFieldElement b);
		public abstract ECFieldElement addOne();
		public abstract ECFieldElement subtract(ECFieldElement b);
		public abstract ECFieldElement multiply(ECFieldElement b);
		public abstract ECFieldElement divide(ECFieldElement b);
		public abstract ECFieldElement negate();
		public abstract ECFieldElement square();
		public abstract ECFieldElement invert();
		public abstract ECFieldElement sqrt();

		public virtual int bitLength()
		{
			return toBigInteger().bitLength();
		}

		public virtual bool isOne()
		{
			return bitLength() == 1;
		}

		public virtual bool isZero()
		{
			return 0 == toBigInteger().signum();
		}

		public virtual ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiply(b).subtract(x.multiply(y));
		}

		public virtual ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiply(b).add(x.multiply(y));
		}

		public virtual ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return square().subtract(x.multiply(y));
		}

		public virtual ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			return square().add(x.multiply(y));
		}

		public virtual ECFieldElement squarePow(int pow)
		{
			ECFieldElement r = this;
			for (int i = 0; i < pow; ++i)
			{
				r = r.square();
			}
			return r;
		}

		public virtual bool testBitZero()
		{
			return toBigInteger().testBit(0);
		}

		public override string ToString()
		{
			return this.toBigInteger().ToString(16);
		}

		public virtual byte[] getEncoded()
		{
			return BigIntegers.asUnsignedByteArray((getFieldSize() + 7) / 8, toBigInteger());
		}

		public abstract class AbstractFp : ECFieldElement
		{
		}

		public class Fp : AbstractFp
		{
			internal BigInteger q, r, x;

			internal static BigInteger calculateResidue(BigInteger p)
			{
				int bitLength = p.bitLength();
				if (bitLength >= 96)
				{
					BigInteger firstWord = p.shiftRight(bitLength - 64);
					if (firstWord.longValue() == -1L)
					{
						return ECConstants_Fields.ONE.shiftLeft(bitLength).subtract(p);
					}
				}
				return null;
			}

			/// @deprecated Use ECCurve.fromBigInteger to construct field elements 
			public Fp(BigInteger q, BigInteger x) : this(q, calculateResidue(q), x)
			{
			}

			public Fp(BigInteger q, BigInteger r, BigInteger x)
			{
				if (x == null || x.signum() < 0 || x.compareTo(q) >= 0)
				{
					throw new IllegalArgumentException("x value invalid in Fp field element");
				}

				this.q = q;
				this.r = r;
				this.x = x;
			}

			public override BigInteger toBigInteger()
			{
				return x;
			}

			/// <summary>
			/// return the field name for this field.
			/// </summary>
			/// <returns> the string "Fp". </returns>
			public override string getFieldName()
			{
				return "Fp";
			}

			public override int getFieldSize()
			{
				return q.bitLength();
			}

			public virtual BigInteger getQ()
			{
				return q;
			}

			public override ECFieldElement add(ECFieldElement b)
			{
				return new Fp(q, r, modAdd(x, b.toBigInteger()));
			}

			public override ECFieldElement addOne()
			{
				BigInteger x2 = x.add(ECConstants_Fields.ONE);
				if (x2.compareTo(q) == 0)
				{
					x2 = ECConstants_Fields.ZERO;
				}
				return new Fp(q, r, x2);
			}

			public override ECFieldElement subtract(ECFieldElement b)
			{
				return new Fp(q, r, modSubtract(x, b.toBigInteger()));
			}

			public override ECFieldElement multiply(ECFieldElement b)
			{
				return new Fp(q, r, modMult(x, b.toBigInteger()));
			}

			public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
			{
				BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
				BigInteger ab = ax.multiply(bx);
				BigInteger xy = xx.multiply(yx);
				return new Fp(q, r, modReduce(ab.subtract(xy)));
			}

			public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
			{
				BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
				BigInteger ab = ax.multiply(bx);
				BigInteger xy = xx.multiply(yx);
				return new Fp(q, r, modReduce(ab.add(xy)));
			}

			public override ECFieldElement divide(ECFieldElement b)
			{
				return new Fp(q, r, modMult(x, modInverse(b.toBigInteger())));
			}

			public override ECFieldElement negate()
			{
				return x.signum() == 0 ? this : new Fp(q, r, q.subtract(x));
			}

			public override ECFieldElement square()
			{
				return new Fp(q, r, modMult(x, x));
			}

			public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
			{
				BigInteger ax = this.x, xx = x.toBigInteger(), yx = y.toBigInteger();
				BigInteger aa = ax.multiply(ax);
				BigInteger xy = xx.multiply(yx);
				return new Fp(q, r, modReduce(aa.subtract(xy)));
			}

			public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
			{
				BigInteger ax = this.x, xx = x.toBigInteger(), yx = y.toBigInteger();
				BigInteger aa = ax.multiply(ax);
				BigInteger xy = xx.multiply(yx);
				return new Fp(q, r, modReduce(aa.add(xy)));
			}

			public override ECFieldElement invert()
			{
				// TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
				return new Fp(q, r, modInverse(x));
			}

			// D.1.4 91
			/// <summary>
			/// return a sqrt root - the routine verifies that the calculation
			/// returns the right value - if none exists it returns null.
			/// </summary>
			public override ECFieldElement sqrt()
			{
				if (this.isZero() || this.isOne()) // earlier JDK compatibility
				{
					return this;
				}

				if (!q.testBit(0))
				{
					throw new RuntimeException("not done yet");
				}

				// note: even though this class implements ECConstants don't be tempted to
				// remove the explicit declaration, some J2ME environments don't cope.

				if (q.testBit(1)) // q == 4m + 3
				{
					BigInteger e = q.shiftRight(2).add(ECConstants_Fields.ONE);
					return checkSqrt(new Fp(q, r, x.modPow(e, q)));
				}

				if (q.testBit(2)) // q == 8m + 5
				{
					BigInteger t1 = x.modPow(q.shiftRight(3), q);
					BigInteger t2 = modMult(t1, x);
					BigInteger t3 = modMult(t2, t1);

					if (t3.Equals(ECConstants_Fields.ONE))
					{
						return checkSqrt(new Fp(q, r, t2));
					}

					// TODO This is constant and could be precomputed
					BigInteger t4 = ECConstants_Fields.TWO.modPow(q.shiftRight(2), q);

					BigInteger y = modMult(t2, t4);

					return checkSqrt(new Fp(q, r, y));
				}

				// q == 8m + 1

				BigInteger legendreExponent = q.shiftRight(1);
				if (!(x.modPow(legendreExponent, q).Equals(ECConstants_Fields.ONE)))
				{
					return null;
				}

				BigInteger X = this.x;
				BigInteger fourX = modDouble(modDouble(X));

				BigInteger k = legendreExponent.add(ECConstants_Fields.ONE), qMinusOne = q.subtract(ECConstants_Fields.ONE);

				BigInteger U, V;
				Random rand = new Random();
				do
				{
					BigInteger P;
					do
					{
						P = new BigInteger(q.bitLength(), rand);
					} while (P.compareTo(q) >= 0 || !modReduce(P.multiply(P).subtract(fourX)).modPow(legendreExponent, q).Equals(qMinusOne));

					BigInteger[] result = lucasSequence(P, X, k);
					U = result[0];
					V = result[1];

					if (modMult(V, V).Equals(fourX))
					{
						return new ECFieldElement.Fp(q, r, modHalfAbs(V));
					}
				} while (U.Equals(ECConstants_Fields.ONE) || U.Equals(qMinusOne));

				return null;
			}

			public virtual ECFieldElement checkSqrt(ECFieldElement z)
			{
				return z.square().Equals(this) ? z : null;
			}

			public virtual BigInteger[] lucasSequence(BigInteger P, BigInteger Q, BigInteger k)
			{
				// TODO Research and apply "common-multiplicand multiplication here"

				int n = k.bitLength();
				int s = k.getLowestSetBit();

				// assert k.testBit(s);

				BigInteger Uh = ECConstants_Fields.ONE;
				BigInteger Vl = ECConstants_Fields.TWO;
				BigInteger Vh = P;
				BigInteger Ql = ECConstants_Fields.ONE;
				BigInteger Qh = ECConstants_Fields.ONE;

				for (int j = n - 1; j >= s + 1; --j)
				{
					Ql = modMult(Ql, Qh);

					if (k.testBit(j))
					{
						Qh = modMult(Ql, Q);
						Uh = modMult(Uh, Vh);
						Vl = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
						Vh = modReduce(Vh.multiply(Vh).subtract(Qh.shiftLeft(1)));
					}
					else
					{
						Qh = Ql;
						Uh = modReduce(Uh.multiply(Vl).subtract(Ql));
						Vh = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
						Vl = modReduce(Vl.multiply(Vl).subtract(Ql.shiftLeft(1)));
					}
				}

				Ql = modMult(Ql, Qh);
				Qh = modMult(Ql, Q);
				Uh = modReduce(Uh.multiply(Vl).subtract(Ql));
				Vl = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
				Ql = modMult(Ql, Qh);

				for (int j = 1; j <= s; ++j)
				{
					Uh = modMult(Uh, Vl);
					Vl = modReduce(Vl.multiply(Vl).subtract(Ql.shiftLeft(1)));
					Ql = modMult(Ql, Ql);
				}

				return new BigInteger[]{Uh, Vl};
			}

			public virtual BigInteger modAdd(BigInteger x1, BigInteger x2)
			{
				BigInteger x3 = x1.add(x2);
				if (x3.compareTo(q) >= 0)
				{
					x3 = x3.subtract(q);
				}
				return x3;
			}

			public virtual BigInteger modDouble(BigInteger x)
			{
				BigInteger _2x = x.shiftLeft(1);
				if (_2x.compareTo(q) >= 0)
				{
					_2x = _2x.subtract(q);
				}
				return _2x;
			}

			public virtual BigInteger modHalf(BigInteger x)
			{
				if (x.testBit(0))
				{
					x = q.add(x);
				}
				return x.shiftRight(1);
			}

			public virtual BigInteger modHalfAbs(BigInteger x)
			{
				if (x.testBit(0))
				{
					x = q.subtract(x);
				}
				return x.shiftRight(1);
			}

			public virtual BigInteger modInverse(BigInteger x)
			{
				int bits = getFieldSize();
				int len = (bits + 31) >> 5;
				uint[] p = Nat.fromBigInteger(bits, q);
				uint[] n = Nat.fromBigInteger(bits, x);
				uint[] z = Nat.create(len);
				Mod.invert(p, n, z);
				return Nat.toBigInteger(len, z);
			}

			public virtual BigInteger modMult(BigInteger x1, BigInteger x2)
			{
				return modReduce(x1.multiply(x2));
			}

			public virtual BigInteger modReduce(BigInteger x)
			{
				if (r != null)
				{
					bool negative = x.signum() < 0;
					if (negative)
					{
						x = x.abs();
					}
					int qLen = q.bitLength();
					bool rIsOne = r.Equals(ECConstants_Fields.ONE);
					while (x.bitLength() > (qLen + 1))
					{
						BigInteger u = x.shiftRight(qLen);
						BigInteger v = x.subtract(u.shiftLeft(qLen));
						if (!rIsOne)
						{
							u = u.multiply(r);
						}
						x = u.add(v);
					}
					while (x.compareTo(q) >= 0)
					{
						x = x.subtract(q);
					}
					if (negative && x.signum() != 0)
					{
						x = q.subtract(x);
					}
				}
				else
				{
					x = x.mod(q);
				}
				return x;
			}

			public virtual BigInteger modSubtract(BigInteger x1, BigInteger x2)
			{
				BigInteger x3 = x1.subtract(x2);
				if (x3.signum() < 0)
				{
					x3 = x3.add(q);
				}
				return x3;
			}

			public override bool Equals(object other)
			{
				if (other == this)
				{
					return true;
				}

				if (!(other is ECFieldElement.Fp))
				{
					return false;
				}

				ECFieldElement.Fp o = (ECFieldElement.Fp)other;
				return q.Equals(o.q) && x.Equals(o.x);
			}

			public override int GetHashCode()
			{
				return q.GetHashCode() ^ x.GetHashCode();
			}
		}

		public abstract class AbstractF2m : ECFieldElement
		{
			public virtual ECFieldElement halfTrace()
			{
				int m = getFieldSize();
				if ((m & 1) == 0)
				{
					throw new IllegalStateException("Half-trace only defined for odd m");
				}

				ECFieldElement fe = this;
				ECFieldElement ht = fe;
				for (int i = 2; i < m; i += 2)
				{
					fe = fe.squarePow(2);
					ht = ht.add(fe);
				}

				return ht;
			}

			public virtual uint trace()
			{
				int m = getFieldSize();
				ECFieldElement fe = this;
				ECFieldElement tr = fe;
				for (int i = 1; i < m; ++i)
				{
					fe = fe.square();
					tr = tr.add(fe);
				}
				if (tr.isZero())
				{
					return 0;
				}
				if (tr.isOne())
				{
					return 1;
				}
				throw new IllegalStateException("Internal error in trace calculation");
			}
		}

		/// <summary>
		/// Class representing the Elements of the finite field
		/// <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
		/// representation. Both trinomial (TPB) and pentanomial (PPB) polynomial
		/// basis representations are supported. Gaussian normal basis (GNB)
		/// representation is not supported.
		/// </summary>
		public class F2m : AbstractF2m
		{
			/// <summary>
			/// Indicates gaussian normal basis representation (GNB). Number chosen
			/// according to X9.62. GNB is not implemented at present.
			/// </summary>
			public const int GNB = 1;

			/// <summary>
			/// Indicates trinomial basis representation (TPB). Number chosen
			/// according to X9.62.
			/// </summary>
			public const int TPB = 2;

			/// <summary>
			/// Indicates pentanomial basis representation (PPB). Number chosen
			/// according to X9.62.
			/// </summary>
			public const int PPB = 3;

			/// <summary>
			/// TPB or PPB.
			/// </summary>
			internal int representation;

			/// <summary>
			/// The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
			/// </summary>
			internal int m;

			internal int[] ks;

			/// <summary>
			/// The <code>LongArray</code> holding the bits.
			/// </summary>
			internal LongArray x;

			/// <summary>
			/// Constructor for PPB. </summary>
			/// <param name="m">  The exponent <code>m</code> of
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="k1"> The integer <code>k1</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>. </param>
			/// <param name="k2"> The integer <code>k2</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>. </param>
			/// <param name="k3"> The integer <code>k3</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>. </param>
			/// <param name="x"> The BigInteger representing the value of the field element. </param>
			/// @deprecated Use ECCurve.fromBigInteger to construct field elements 
			public F2m(int m, int k1, int k2, int k3, BigInteger x)
			{
				if (x == null || x.signum() < 0 || x.bitLength() > m)
				{
					throw new IllegalArgumentException("x value invalid in F2m field element");
				}

				if ((k2 == 0) && (k3 == 0))
				{
					this.representation = TPB;
					this.ks = new int[]{k1};
				}
				else
				{
					if (k2 >= k3)
					{
						throw new IllegalArgumentException("k2 must be smaller than k3");
					}
					if (k2 <= 0)
					{
						throw new IllegalArgumentException("k2 must be larger than 0");
					}
					this.representation = PPB;
					this.ks = new int[]{k1, k2, k3};
				}

				this.m = m;
				this.x = new LongArray(x);
			}

			public F2m(int m, int[] ks, LongArray x)
			{
				this.m = m;
				this.representation = (ks.Length == 1) ? TPB : PPB;
				this.ks = ks;
				this.x = x;
			}

			public override int bitLength()
			{
				return x.degree();
			}

			public override bool isOne()
			{
				return x.isOne();
			}

			public override bool isZero()
			{
				return x.isZero();
			}

			public override bool testBitZero()
			{
				return x.testBitZero();
			}

			public override BigInteger toBigInteger()
			{
				return x.toBigInteger();
			}

			public override string getFieldName()
			{
				return "F2m";
			}

			public override int getFieldSize()
			{
				return m;
			}

			/// <summary>
			/// Checks, if the ECFieldElements <code>a</code> and <code>b</code>
			/// are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
			/// (having the same representation). </summary>
			/// <param name="a"> field element. </param>
			/// <param name="b"> field element to be compared. </param>
			/// <exception cref="IllegalArgumentException"> if <code>a</code> and <code>b</code>
			/// are not elements of the same field
			/// <code>F<sub>2<sup>m</sup></sub></code> (having the same
			/// representation).  </exception>
			public static void checkFieldElements(ECFieldElement a, ECFieldElement b)
			{
				if ((!(a is F2m)) || (!(b is F2m)))
				{
					throw new IllegalArgumentException("Field elements are not " + "both instances of ECFieldElement.F2m");
				}

				ECFieldElement.F2m aF2m = (ECFieldElement.F2m)a;
				ECFieldElement.F2m bF2m = (ECFieldElement.F2m)b;

				if (aF2m.representation != bF2m.representation)
				{
					// Should never occur
					throw new IllegalArgumentException("One of the F2m field elements has incorrect representation");
				}

				if ((aF2m.m != bF2m.m) || !Arrays.areEqual(aF2m.ks, bF2m.ks))
				{
					throw new IllegalArgumentException("Field elements are not elements of the same field F2m");
				}
			}


			public override ECFieldElement add(ECFieldElement b)
			{
				// No check performed here for performance reasons. Instead the
				// elements involved are checked in ECPoint.F2m
				// checkFieldElements(this, b);
				LongArray iarrClone = (LongArray)this.x.clone();
				F2m bF2m = (F2m)b;
				iarrClone.addShiftedByWords(bF2m.x, 0);
				return new F2m(m, ks, iarrClone);
			}

			public override ECFieldElement addOne()
			{
				return new F2m(m, ks, x.addOne());
			}


			public override ECFieldElement subtract(ECFieldElement b)
			{
				// Addition and subtraction are the same in F2m
				return add(b);
			}


			public override ECFieldElement multiply(ECFieldElement b)
			{
				// Right-to-left comb multiplication in the LongArray
				// Input: Binary polynomials a(z) and b(z) of degree at most m-1
				// Output: c(z) = a(z) * b(z) mod f(z)

				// No check performed here for performance reasons. Instead the
				// elements involved are checked in ECPoint.F2m
				// checkFieldElements(this, b);
				return new F2m(m, ks, x.modMultiply(((F2m)b).x, m, ks));
			}

			public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
			{
				return multiplyPlusProduct(b, x, y);
			}

			public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
			{
				LongArray ax = this.x, bx = ((F2m)b).x, xx = ((F2m)x).x, yx = ((F2m)y).x;

				LongArray ab = ax.multiply(bx, m, ks);
				LongArray xy = xx.multiply(yx, m, ks);

				if (ab == ax || ab == bx)
				{
					ab = (LongArray)ab.clone();
				}

				ab.addShiftedByWords(xy, 0);
				ab.reduce(m, ks);

				return new F2m(m, ks, ab);
			}


			public override ECFieldElement divide(ECFieldElement b)
			{
				// There may be more efficient implementations
				ECFieldElement bInv = b.invert();
				return multiply(bInv);
			}

			public override ECFieldElement negate()
			{
				// -x == x holds for all x in F2m
				return this;
			}

			public override ECFieldElement square()
			{
				return new F2m(m, ks, x.modSquare(m, ks));
			}

			public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
			{
				return squarePlusProduct(x, y);
			}

			public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
			{
				LongArray ax = this.x, xx = ((F2m)x).x, yx = ((F2m)y).x;

				LongArray aa = ax.square(m, ks);
				LongArray xy = xx.multiply(yx, m, ks);

				if (aa == ax)
				{
					aa = (LongArray)aa.clone();
				}

				aa.addShiftedByWords(xy, 0);
				aa.reduce(m, ks);

				return new F2m(m, ks, aa);
			}

			public override ECFieldElement squarePow(int pow)
			{
				return pow < 1 ? this : new F2m(m, ks, x.modSquareN(pow, m, ks));
			}

			public override ECFieldElement invert()
			{
				return new ECFieldElement.F2m(this.m, this.ks, this.x.modInverse(m, ks));
			}

			public override ECFieldElement sqrt()
			{
				return (x.isZero() || x.isOne()) ? this : squarePow(m - 1);
			}

			/// <returns> the representation of the field
			/// <code>F<sub>2<sup>m</sup></sub></code>, either of
			/// TPB (trinomial
			/// basis representation) or
			/// PPB (pentanomial
			/// basis representation). </returns>
			public virtual int getRepresentation()
			{
				return this.representation;
			}

			/// <returns> the degree <code>m</code> of the reduction polynomial
			/// <code>f(z)</code>. </returns>
			public virtual int getM()
			{
				return this.m;
			}

			/// <returns> TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
			/// x<sup>k</sup> + 1</code> represents the reduction polynomial
			/// <code>f(z)</code>.<br>
			/// PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br> </returns>
			public virtual int getK1()
			{
				return this.ks[0];
			}

			/// <returns> TPB: Always returns <code>0</code><br>
			/// PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br> </returns>
			public virtual int getK2()
			{
				return this.ks.Length >= 2 ? this.ks[1] : 0;
			}

			/// <returns> TPB: Always set to <code>0</code><br>
			/// PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br> </returns>
			public virtual int getK3()
			{
				return this.ks.Length >= 3 ? this.ks[2] : 0;
			}

			public override bool Equals(object anObject)
			{
				if (anObject == this)
				{
					return true;
				}

				if (!(anObject is ECFieldElement.F2m))
				{
					return false;
				}

				ECFieldElement.F2m b = (ECFieldElement.F2m)anObject;

				return ((this.m == b.m) && (this.representation == b.representation) && Arrays.areEqual(this.ks, b.ks) && (this.x.Equals(b.x)));
			}

			public override int GetHashCode()
			{
				return x.GetHashCode() ^ m ^ Arrays.GetHashCode(ks);
			}
		}
	}

}