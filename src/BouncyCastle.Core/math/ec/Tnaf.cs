using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Class holding methods for point multiplication based on the window
	/// &tau;-adic nonadjacent form (WTNAF). The algorithms are based on the
	/// paper "Improved Algorithms for Arithmetic on Anomalous Binary Curves"
	/// by Jerome A. Solinas. The paper first appeared in the Proceedings of
	/// Crypto 1997.
	/// </summary>
	public class Tnaf
	{
		private static readonly BigInteger MINUS_ONE = ECConstants_Fields.ONE.negate();
		private static readonly BigInteger MINUS_TWO = ECConstants_Fields.TWO.negate();
		private static readonly BigInteger MINUS_THREE = ECConstants_Fields.THREE.negate();

		/// <summary>
		/// The window width of WTNAF. The standard value of 4 is slightly less
		/// than optimal for running time, but keeps space requirements for
		/// precomputation low. For typical curves, a value of 5 or 6 results in
		/// a better running time. When changing this value, the
		/// <code>&alpha;<sub>u</sub></code>'s must be computed differently, see
		/// e.g. "Guide to Elliptic Curve Cryptography", Darrel Hankerson,
		/// Alfred Menezes, Scott Vanstone, Springer-Verlag New York Inc., 2004,
		/// p. 121-122
		/// </summary>
		public const byte WIDTH = 4;

		/// <summary>
		/// 2<sup>4</sup>
		/// </summary>
		public const byte POW_2_WIDTH = 16;

		/// <summary>
		/// The <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array
		/// of <code>ZTauElement</code>s.
		/// </summary>
		public static readonly ZTauElement[] alpha0 = new ZTauElement[] {null, new ZTauElement(ECConstants_Fields.ONE, ECConstants_Fields.ZERO), null, new ZTauElement(MINUS_THREE, MINUS_ONE), null, new ZTauElement(MINUS_ONE, MINUS_ONE), null, new ZTauElement(ECConstants_Fields.ONE, MINUS_ONE), null};

		/// <summary>
		/// The <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array
		/// of TNAFs.
		/// </summary>
		public static readonly byte[][] alpha0Tnaf = new byte[][]
		{
			null, new byte[] {1},
			null, new byte[] {-1, 0, 1},
			null, new byte[] {1, 0, 1},
			null, new byte[] {-1, 0, 0, 1}
		};

		/// <summary>
		/// The <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array
		/// of <code>ZTauElement</code>s.
		/// </summary>
		public static readonly ZTauElement[] alpha1 = new ZTauElement[] {null, new ZTauElement(ECConstants_Fields.ONE, ECConstants_Fields.ZERO), null, new ZTauElement(MINUS_THREE, ECConstants_Fields.ONE), null, new ZTauElement(MINUS_ONE, ECConstants_Fields.ONE), null, new ZTauElement(ECConstants_Fields.ONE, ECConstants_Fields.ONE), null};

		/// <summary>
		/// The <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array
		/// of TNAFs.
		/// </summary>
		public static readonly byte[][] alpha1Tnaf = new byte[][]
		{
			null, new byte[] {1},
			null, new byte[] {-1, 0, 1},
			null, new byte[] {1, 0, 1},
			null, new byte[] {-1, 0, 0, -1}
		};

		/// <summary>
		/// Computes the norm of an element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code>. </summary>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. </param>
		/// <param name="lambda"> The element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code>. </param>
		/// <returns> The norm of <code>&lambda;</code>. </returns>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static java.math.BigInteger norm(final byte mu, ZTauElement lambda)
		public static BigInteger norm(byte mu, ZTauElement lambda)
		{
			BigInteger norm;

			// s1 = u^2
			BigInteger s1 = lambda.u.multiply(lambda.u);

			// s2 = u * v
			BigInteger s2 = lambda.u.multiply(lambda.v);

			// s3 = 2 * v^2
			BigInteger s3 = lambda.v.multiply(lambda.v).shiftLeft(1);

			if (mu == 1)
			{
				norm = s1.add(s2).add(s3);
			}
			else if (mu == -1)
			{
				norm = s1.subtract(s2).add(s3);
			}
			else
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			return norm;
		}

		/// <summary>
		/// Computes the norm of an element <code>&lambda;</code> of
		/// <code><b>R</b>[&tau;]</code>, where <code>&lambda; = u + v&tau;</code>
		/// and <code>u</code> and <code>u</code> are real numbers (elements of
		/// <code><b>R</b></code>). </summary>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. </param>
		/// <param name="u"> The real part of the element <code>&lambda;</code> of
		/// <code><b>R</b>[&tau;]</code>. </param>
		/// <param name="v"> The <code>&tau;</code>-adic part of the element
		/// <code>&lambda;</code> of <code><b>R</b>[&tau;]</code>. </param>
		/// <returns> The norm of <code>&lambda;</code>. </returns>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static SimpleBigDecimal norm(final byte mu, SimpleBigDecimal u, SimpleBigDecimal v)
		public static SimpleBigDecimal norm(byte mu, SimpleBigDecimal u, SimpleBigDecimal v)
		{
			SimpleBigDecimal norm;

			// s1 = u^2
			SimpleBigDecimal s1 = u.multiply(u);

			// s2 = u * v
			SimpleBigDecimal s2 = u.multiply(v);

			// s3 = 2 * v^2
			SimpleBigDecimal s3 = v.multiply(v).shiftLeft(1);

			if (mu == 1)
			{
				norm = s1.add(s2).add(s3);
			}
			else if (mu == -1)
			{
				norm = s1.subtract(s2).add(s3);
			}
			else
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			return norm;
		}

		/// <summary>
		/// Rounds an element <code>&lambda;</code> of <code><b>R</b>[&tau;]</code>
		/// to an element of <code><b>Z</b>[&tau;]</code>, such that their difference
		/// has minimal norm. <code>&lambda;</code> is given as
		/// <code>&lambda; = &lambda;<sub>0</sub> + &lambda;<sub>1</sub>&tau;</code>. </summary>
		/// <param name="lambda0"> The component <code>&lambda;<sub>0</sub></code>. </param>
		/// <param name="lambda1"> The component <code>&lambda;<sub>1</sub></code>. </param>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. Must
		/// equal 1 or -1. </param>
		/// <returns> The rounded element of <code><b>Z</b>[&tau;]</code>. </returns>
		/// <exception cref="IllegalArgumentException"> if <code>lambda0</code> and
		/// <code>lambda1</code> do not have same scale. </exception>
		public static ZTauElement round(SimpleBigDecimal lambda0, SimpleBigDecimal lambda1, byte mu)
		{
			int scale = lambda0.getScale();
			if (lambda1.getScale() != scale)
			{
				throw new IllegalArgumentException("lambda0 and lambda1 do not " + "have same scale");
			}

			if (!((mu == 1) || (mu == -1)))
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			BigInteger f0 = lambda0.round();
			BigInteger f1 = lambda1.round();

			SimpleBigDecimal eta0 = lambda0.subtract(f0);
			SimpleBigDecimal eta1 = lambda1.subtract(f1);

			// eta = 2*eta0 + mu*eta1
			SimpleBigDecimal eta = eta0.add(eta0);
			if (mu == 1)
			{
				eta = eta.add(eta1);
			}
			else
			{
				// mu == -1
				eta = eta.subtract(eta1);
			}

			// check1 = eta0 - 3*mu*eta1
			// check2 = eta0 + 4*mu*eta1
			SimpleBigDecimal threeEta1 = eta1.add(eta1).add(eta1);
			SimpleBigDecimal fourEta1 = threeEta1.add(eta1);
			SimpleBigDecimal check1;
			SimpleBigDecimal check2;
			if (mu == 1)
			{
				check1 = eta0.subtract(threeEta1);
				check2 = eta0.add(fourEta1);
			}
			else
			{
				// mu == -1
				check1 = eta0.add(threeEta1);
				check2 = eta0.subtract(fourEta1);
			}

			byte h0 = 0;
			byte h1 = 0;

			// if eta >= 1
			if (eta.compareTo(ECConstants_Fields.ONE) >= 0)
			{
				if (check1.compareTo(MINUS_ONE) < 0)
				{
					h1 = mu;
				}
				else
				{
					h0 = 1;
				}
			}
			else
			{
				// eta < 1
				if (check2.compareTo(ECConstants_Fields.TWO) >= 0)
				{
					h1 = mu;
				}
			}

			// if eta < -1
			if (eta.compareTo(MINUS_ONE) < 0)
			{
				if (check1.compareTo(ECConstants_Fields.ONE) >= 0)
				{
					h1 = (byte)-mu;
				}
				else
				{
					h0 = -1;
				}
			}
			else
			{
				// eta >= -1
				if (check2.compareTo(MINUS_TWO) < 0)
				{
					h1 = (byte)-mu;
				}
			}

			BigInteger q0 = f0.add(BigInteger.valueOf(h0));
			BigInteger q1 = f1.add(BigInteger.valueOf(h1));
			return new ZTauElement(q0, q1);
		}

		/// <summary>
		/// Approximate division by <code>n</code>. For an integer
		/// <code>k</code>, the value <code>&lambda; = s k / n</code> is
		/// computed to <code>c</code> bits of accuracy. </summary>
		/// <param name="k"> The parameter <code>k</code>. </param>
		/// <param name="s"> The curve parameter <code>s<sub>0</sub></code> or
		/// <code>s<sub>1</sub></code>. </param>
		/// <param name="vm"> The Lucas Sequence element <code>V<sub>m</sub></code>. </param>
		/// <param name="a"> The parameter <code>a</code> of the elliptic curve. </param>
		/// <param name="m"> The bit length of the finite field
		/// <code><b>F</b><sub>m</sub></code>. </param>
		/// <param name="c"> The number of bits of accuracy, i.e. the scale of the returned
		/// <code>SimpleBigDecimal</code>. </param>
		/// <returns> The value <code>&lambda; = s k / n</code> computed to
		/// <code>c</code> bits of accuracy. </returns>
		public static SimpleBigDecimal approximateDivisionByN(BigInteger k, BigInteger s, BigInteger vm, byte a, int m, int c)
		{
			int _k = (m + 5) / 2 + c;
			BigInteger ns = k.shiftRight(m - _k - 2 + a);

			BigInteger gs = s.multiply(ns);

			BigInteger hs = gs.shiftRight(m);

			BigInteger js = vm.multiply(hs);

			BigInteger gsPlusJs = gs.add(js);
			BigInteger ls = gsPlusJs.shiftRight(_k - c);
			if (gsPlusJs.testBit(_k - c - 1))
			{
				// round up
				ls = ls.add(ECConstants_Fields.ONE);
			}

			return new SimpleBigDecimal(ls, c);
		}

		/// <summary>
		/// Computes the <code>&tau;</code>-adic NAF (non-adjacent form) of an
		/// element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>. </summary>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. </param>
		/// <param name="lambda"> The element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code>. </param>
		/// <returns> The <code>&tau;</code>-adic NAF of <code>&lambda;</code>. </returns>
		public static byte[] tauAdicNaf(byte mu, ZTauElement lambda)
		{
			if (!((mu == 1) || (mu == -1)))
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			BigInteger norm = norm(mu, lambda);

			// Ceiling of log2 of the norm 
			int log2Norm = norm.bitLength();

			// If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
			int maxLength = log2Norm > 30 ? log2Norm + 4 : 34;

			// The array holding the TNAF
			byte[] u = new byte[maxLength];
			int i = 0;

			// The actual length of the TNAF
			int length = 0;

			BigInteger r0 = lambda.u;
			BigInteger r1 = lambda.v;

			while (!((r0.Equals(ECConstants_Fields.ZERO)) && (r1.Equals(ECConstants_Fields.ZERO))))
			{
				// If r0 is odd
				if (r0.testBit(0))
				{
					u[i] = (byte) ECConstants_Fields.TWO.subtract((r0.subtract(r1.shiftLeft(1))).mod(ECConstants_Fields.FOUR)).intValue();

					// r0 = r0 - u[i]
					if (u[i] == 1)
					{
						r0 = r0.clearBit(0);
					}
					else
					{
						// u[i] == -1
						r0 = r0.add(ECConstants_Fields.ONE);
					}
					length = i;
				}
				else
				{
					u[i] = 0;
				}

				BigInteger t = r0;
				BigInteger s = r0.shiftRight(1);
				if (mu == 1)
				{
					r0 = r1.add(s);
				}
				else
				{
					// mu == -1
					r0 = r1.subtract(s);
				}

				r1 = t.shiftRight(1).negate();
				i++;
			}

			length++;

			// Reduce the TNAF array to its actual length
			byte[] tnaf = new byte[length];
			JavaSystem.arraycopy(u, 0, tnaf, 0, length);
			return tnaf;
		}

		/// <summary>
		/// Applies the operation <code>&tau;()</code> to an
		/// <code>ECPoint.AbstractF2m</code>. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to which <code>&tau;()</code> is applied. </param>
		/// <returns> <code>&tau;(p)</code> </returns>
		public static ECPoint.AbstractF2m tau(ECPoint.AbstractF2m p)
		{
			return p.tau();
		}

		/// <summary>
		/// Returns the parameter <code>&mu;</code> of the elliptic curve. </summary>
		/// <param name="curve"> The elliptic curve from which to obtain <code>&mu;</code>.
		/// The curve must be a Koblitz curve, i.e. <code>a</code> equals
		/// <code>0</code> or <code>1</code> and <code>b</code> equals
		/// <code>1</code>. </param>
		/// <returns> <code>&mu;</code> of the elliptic curve. </returns>
		/// <exception cref="IllegalArgumentException"> if the given ECCurve is not a Koblitz
		/// curve. </exception>
		public static byte getMu(ECCurve.AbstractF2m curve)
		{
			if (!curve.isKoblitz())
			{
				throw new IllegalArgumentException("No Koblitz curve (ABC), TNAF multiplication not possible");
			}

			if (curve.getA().isZero())
			{
				return -1;
			}

			return 1;
		}

		public static byte getMu(ECFieldElement curveA)
		{
			return (byte)(curveA.isZero() ? -1 : 1);
		}

		public static byte getMu(int curveA)
		{
			return (byte)(curveA == 0 ? -1 : 1);
		}

		/// <summary>
		/// Calculates the Lucas Sequence elements <code>U<sub>k-1</sub></code> and
		/// <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code> and
		/// <code>V<sub>k</sub></code>. </summary>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. </param>
		/// <param name="k"> The index of the second element of the Lucas Sequence to be
		/// returned. </param>
		/// <param name="doV"> If set to true, computes <code>V<sub>k-1</sub></code> and
		/// <code>V<sub>k</sub></code>, otherwise <code>U<sub>k-1</sub></code> and
		/// <code>U<sub>k</sub></code>. </param>
		/// <returns> An array with 2 elements, containing <code>U<sub>k-1</sub></code>
		/// and <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code>
		/// and <code>V<sub>k</sub></code>. </returns>
		public static BigInteger[] getLucas(byte mu, int k, bool doV)
		{
			if (!((mu == 1) || (mu == -1)))
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			BigInteger u0;
			BigInteger u1;
			BigInteger u2;

			if (doV)
			{
				u0 = ECConstants_Fields.TWO;
				u1 = BigInteger.valueOf(mu);
			}
			else
			{
				u0 = ECConstants_Fields.ZERO;
				u1 = ECConstants_Fields.ONE;
			}

			for (int i = 1; i < k; i++)
			{
				// u2 = mu*u1 - 2*u0;
				BigInteger s = null;
				if (mu == 1)
				{
					s = u1;
				}
				else
				{
					// mu == -1
					s = u1.negate();
				}

				u2 = s.subtract(u0.shiftLeft(1));
				u0 = u1;
				u1 = u2;
	//            JavaSystem.@out.println(i + ": " + u2);
	//            JavaSystem.@out.println();
			}

			BigInteger[] retVal = new BigInteger[] {u0, u1};
			return retVal;
		}

		/// <summary>
		/// Computes the auxiliary value <code>t<sub>w</sub></code>. If the width is
		/// 4, then for <code>mu = 1</code>, <code>t<sub>w</sub> = 6</code> and for
		/// <code>mu = -1</code>, <code>t<sub>w</sub> = 10</code> </summary>
		/// <param name="mu"> The parameter <code>&mu;</code> of the elliptic curve. </param>
		/// <param name="w"> The window width of the WTNAF. </param>
		/// <returns> the auxiliary value <code>t<sub>w</sub></code> </returns>
		public static BigInteger getTw(byte mu, int w)
		{
			if (w == 4)
			{
				if (mu == 1)
				{
					return BigInteger.valueOf(6);
				}
				else
				{
					// mu == -1
					return BigInteger.valueOf(10);
				}
			}
			else
			{
				// For w <> 4, the values must be computed
				BigInteger[] us = getLucas(mu, w, false);
				BigInteger twoToW = ECConstants_Fields.ZERO.setBit(w);
				BigInteger u1invert = us[1].modInverse(twoToW);
				BigInteger tw;
				tw = ECConstants_Fields.TWO.multiply(us[0]).multiply(u1invert).mod(twoToW);
	//            JavaSystem.@out.println("mu = " + mu);
	//            JavaSystem.@out.println("tw = " + tw);
				return tw;
			}
		}

		/// <summary>
		/// Computes the auxiliary values <code>s<sub>0</sub></code> and
		/// <code>s<sub>1</sub></code> used for partial modular reduction. </summary>
		/// <param name="curve"> The elliptic curve for which to compute
		/// <code>s<sub>0</sub></code> and <code>s<sub>1</sub></code>. </param>
		/// <exception cref="IllegalArgumentException"> if <code>curve</code> is not a
		/// Koblitz curve (Anomalous Binary Curve, ABC). </exception>
		public static BigInteger[] getSi(ECCurve.AbstractF2m curve)
		{
			if (!curve.isKoblitz())
			{
				throw new IllegalArgumentException("si is defined for Koblitz curves only");
			}

			int m = curve.getFieldSize();
			int a = curve.getA().toBigInteger().intValue();
			byte mu = getMu(a);
			int shifts = getShiftsForCofactor(curve.getCofactor());
			int index = m + 3 - a;
			BigInteger[] ui = getLucas(mu, index, false);
			if (mu == 1)
			{
				ui[0] = ui[0].negate();
				ui[1] = ui[1].negate();
			}

			BigInteger dividend0 = ECConstants_Fields.ONE.add(ui[1]).shiftRight(shifts);
			BigInteger dividend1 = ECConstants_Fields.ONE.add(ui[0]).shiftRight(shifts).negate();

			return new BigInteger[] {dividend0, dividend1};
		}

		public static BigInteger[] getSi(int fieldSize, int curveA, BigInteger cofactor)
		{
			byte mu = getMu(curveA);
			int shifts = getShiftsForCofactor(cofactor);
			int index = fieldSize + 3 - curveA;
			BigInteger[] ui = getLucas(mu, index, false);
			if (mu == 1)
			{
				ui[0] = ui[0].negate();
				ui[1] = ui[1].negate();
			}

			BigInteger dividend0 = ECConstants_Fields.ONE.add(ui[1]).shiftRight(shifts);
			BigInteger dividend1 = ECConstants_Fields.ONE.add(ui[0]).shiftRight(shifts).negate();

			return new BigInteger[] {dividend0, dividend1};
		}

		protected internal static int getShiftsForCofactor(BigInteger h)
		{
			if (h != null)
			{
				if (h.Equals(ECConstants_Fields.TWO))
				{
					return 1;
				}
				if (h.Equals(ECConstants_Fields.FOUR))
				{
					return 2;
				}
			}

			throw new IllegalArgumentException("h (Cofactor) must be 2 or 4");
		}

		/// <summary>
		/// Partial modular reduction modulo
		/// <code>(&tau;<sup>m</sup> - 1)/(&tau; - 1)</code>. </summary>
		/// <param name="k"> The integer to be reduced. </param>
		/// <param name="m"> The bitlength of the underlying finite field. </param>
		/// <param name="a"> The parameter <code>a</code> of the elliptic curve. </param>
		/// <param name="s"> The auxiliary values <code>s<sub>0</sub></code> and
		/// <code>s<sub>1</sub></code>. </param>
		/// <param name="mu"> The parameter &mu; of the elliptic curve. </param>
		/// <param name="c"> The precision (number of bits of accuracy) of the partial
		/// modular reduction. </param>
		/// <returns> <code>&rho; := k partmod (&tau;<sup>m</sup> - 1)/(&tau; - 1)</code> </returns>
		public static ZTauElement partModReduction(BigInteger k, int m, byte a, BigInteger[] s, byte mu, byte c)
		{
			// d0 = s[0] + mu*s[1]; mu is either 1 or -1
			BigInteger d0;
			if (mu == 1)
			{
				d0 = s[0].add(s[1]);
			}
			else
			{
				d0 = s[0].subtract(s[1]);
			}

			BigInteger[] v = getLucas(mu, m, true);
			BigInteger vm = v[1];

			SimpleBigDecimal lambda0 = approximateDivisionByN(k, s[0], vm, a, m, c);

			SimpleBigDecimal lambda1 = approximateDivisionByN(k, s[1], vm, a, m, c);

			ZTauElement q = round(lambda0, lambda1, mu);

			// r0 = n - d0*q0 - 2*s1*q1
			BigInteger r0 = k.subtract(d0.multiply(q.u)).subtract(BigInteger.valueOf(2).multiply(s[1]).multiply(q.v));

			// r1 = s1*q0 - s0*q1
			BigInteger r1 = s[1].multiply(q.u).subtract(s[0].multiply(q.v));

			return new ZTauElement(r0, r1);
		}

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by a <code>BigInteger</code> using the reduced <code>&tau;</code>-adic
		/// NAF (RTNAF) method. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="k"> The <code>BigInteger</code> by which to multiply <code>p</code>. </param>
		/// <returns> <code>k * p</code> </returns>
		public static ECPoint.AbstractF2m multiplyRTnaf(ECPoint.AbstractF2m p, BigInteger k)
		{
			ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m) p.getCurve();
			int m = curve.getFieldSize();
			int a = curve.getA().toBigInteger().intValue();
			byte mu = getMu(a);
			BigInteger[] s = curve.getSi();
			ZTauElement rho = partModReduction(k, m, (byte)a, s, mu, (byte)10);

			return multiplyTnaf(p, rho);
		}

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>
		/// using the <code>&tau;</code>-adic NAF (TNAF) method. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="lambda"> The element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code>. </param>
		/// <returns> <code>&lambda; * p</code> </returns>
		public static ECPoint.AbstractF2m multiplyTnaf(ECPoint.AbstractF2m p, ZTauElement lambda)
		{
			ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)p.getCurve();
			byte mu = getMu(curve.getA());
			byte[] u = tauAdicNaf(mu, lambda);

			ECPoint.AbstractF2m q = multiplyFromTnaf(p, u);

			return q;
		}

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>
		/// using the <code>&tau;</code>-adic NAF (TNAF) method, given the TNAF
		/// of <code>&lambda;</code>. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="u"> The the TNAF of <code>&lambda;</code>.. </param>
		/// <returns> <code>&lambda; * p</code> </returns>
		public static ECPoint.AbstractF2m multiplyFromTnaf(ECPoint.AbstractF2m p, byte[] u)
		{
			ECCurve curve = p.getCurve();
			ECPoint.AbstractF2m q = (ECPoint.AbstractF2m)curve.getInfinity();
			ECPoint.AbstractF2m pNeg = (ECPoint.AbstractF2m)p.negate();
			int tauCount = 0;
			for (int i = u.Length - 1; i >= 0; i--)
			{
				++tauCount;
				byte ui = u[i];
				if (ui != 0)
				{
					q = q.tauPow(tauCount);
					tauCount = 0;

					ECPoint x = ui > 0 ? p : pNeg;
					q = (ECPoint.AbstractF2m)q.add(x);
				}
			}
			if (tauCount > 0)
			{
				q = q.tauPow(tauCount);
			}
			return q;
		}

		/// <summary>
		/// Computes the <code>[&tau;]</code>-adic window NAF of an element
		/// <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>. </summary>
		/// <param name="mu"> The parameter &mu; of the elliptic curve. </param>
		/// <param name="lambda"> The element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code> of which to compute the
		/// <code>[&tau;]</code>-adic NAF. </param>
		/// <param name="width"> The window width of the resulting WNAF. </param>
		/// <param name="pow2w"> 2<sup>width</sup>. </param>
		/// <param name="tw"> The auxiliary value <code>t<sub>w</sub></code>. </param>
		/// <param name="alpha"> The <code>&alpha;<sub>u</sub></code>'s for the window width. </param>
		/// <returns> The <code>[&tau;]</code>-adic window NAF of
		/// <code>&lambda;</code>. </returns>
		public static byte[] tauAdicWNaf(byte mu, ZTauElement lambda, byte width, BigInteger pow2w, BigInteger tw, ZTauElement[] alpha)
		{
			if (!((mu == 1) || (mu == -1)))
			{
				throw new IllegalArgumentException("mu must be 1 or -1");
			}

			BigInteger norm = norm(mu, lambda);

			// Ceiling of log2 of the norm 
			int log2Norm = norm.bitLength();

			// If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
			int maxLength = log2Norm > 30 ? log2Norm + 4 + width : 34 + width;

			// The array holding the TNAF
			byte[] u = new byte[maxLength];

			// 2^(width - 1)
			BigInteger pow2wMin1 = pow2w.shiftRight(1);

			// Split lambda into two BigIntegers to simplify calculations
			BigInteger r0 = lambda.u;
			BigInteger r1 = lambda.v;
			int i = 0;

			// while lambda <> (0, 0)
			while (!((r0.Equals(ECConstants_Fields.ZERO)) && (r1.Equals(ECConstants_Fields.ZERO))))
			{
				// if r0 is odd
				if (r0.testBit(0))
				{
					// uUnMod = r0 + r1*tw mod 2^width
					BigInteger uUnMod = r0.add(r1.multiply(tw)).mod(pow2w);

					byte uLocal;
					// if uUnMod >= 2^(width - 1)
					if (uUnMod.compareTo(pow2wMin1) >= 0)
					{
						uLocal = (byte) uUnMod.subtract(pow2w).intValue();
					}
					else
					{
						uLocal = (byte) uUnMod.intValue();
					}
					// uLocal is now in [-2^(width-1), 2^(width-1)-1]

					u[i] = uLocal;
					bool s = true;
					if (uLocal < 0)
					{
						s = false;
						uLocal = (byte)-uLocal;
					}
					// uLocal is now >= 0

					if (s)
					{
						r0 = r0.subtract(alpha[uLocal].u);
						r1 = r1.subtract(alpha[uLocal].v);
					}
					else
					{
						r0 = r0.add(alpha[uLocal].u);
						r1 = r1.add(alpha[uLocal].v);
					}
				}
				else
				{
					u[i] = 0;
				}

				BigInteger t = r0;

				if (mu == 1)
				{
					r0 = r1.add(r0.shiftRight(1));
				}
				else
				{
					// mu == -1
					r0 = r1.subtract(r0.shiftRight(1));
				}
				r1 = t.shiftRight(1).negate();
				i++;
			}
			return u;
		}

		/// <summary>
		/// Does the precomputation for WTNAF multiplication. </summary>
		/// <param name="p"> The <code>ECPoint</code> for which to do the precomputation. </param>
		/// <param name="a"> The parameter <code>a</code> of the elliptic curve. </param>
		/// <returns> The precomputation array for <code>p</code>.  </returns>
		public static ECPoint.AbstractF2m[] getPreComp(ECPoint.AbstractF2m p, byte a)
		{
			byte[][] alphaTnaf = (a == 0) ? Tnaf.alpha0Tnaf : Tnaf.alpha1Tnaf;

			ECPoint.AbstractF2m[] pu = new ECPoint.AbstractF2m[(int)((uint)(alphaTnaf.Length + 1) >> 1)];
			pu[0] = p;

			int precompLen = alphaTnaf.Length;
			for (int i = 3; i < precompLen; i += 2)
			{
				pu[(int)((uint)i >> 1)] = Tnaf.multiplyFromTnaf(p, alphaTnaf[i]);
			}

			p.getCurve().normalizeAll(pu);

			return pu;
		}
	}

}