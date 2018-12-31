using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec.endo;
using org.bouncycastle.math.field;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;
using Random = org.bouncycastle.Port.java.util.Random;

namespace org.bouncycastle.math.ec
{

						
	/// <summary>
	/// base class for an elliptic curve
	/// </summary>
	public abstract class ECCurve
	{
		public const int COORD_AFFINE = 0;
		public const int COORD_HOMOGENEOUS = 1;
		public const int COORD_JACOBIAN = 2;
		public const int COORD_JACOBIAN_CHUDNOVSKY = 3;
		public const int COORD_JACOBIAN_MODIFIED = 4;
		public const int COORD_LAMBDA_AFFINE = 5;
		public const int COORD_LAMBDA_PROJECTIVE = 6;
		public const int COORD_SKEWED = 7;

		public static int[] getAllCoordinateSystems()
		{
			return new int[]{COORD_AFFINE, COORD_HOMOGENEOUS, COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY, COORD_JACOBIAN_MODIFIED, COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED};
		}

		public class Config
		{
			private readonly ECCurve outerInstance;

			protected internal int coord;
			protected internal ECEndomorphism endomorphism;
			protected internal ECMultiplier multiplier;

			public Config(ECCurve outerInstance, int coord, ECEndomorphism endomorphism, ECMultiplier multiplier)
			{
				this.outerInstance = outerInstance;
				this.coord = coord;
				this.endomorphism = endomorphism;
				this.multiplier = multiplier;
			}

			public virtual Config setCoordinateSystem(int coord)
			{
				this.coord = coord;
				return this;
			}

			public virtual Config setEndomorphism(ECEndomorphism endomorphism)
			{
				this.endomorphism = endomorphism;
				return this;
			}

			public virtual Config setMultiplier(ECMultiplier multiplier)
			{
				this.multiplier = multiplier;
				return this;
			}

			public virtual ECCurve create()
			{
				if (!outerInstance.supportsCoordinateSystem(coord))
				{
					throw new IllegalStateException("unsupported coordinate system");
				}

				ECCurve c = outerInstance.cloneCurve();
				if (c == outerInstance)
				{
					throw new IllegalStateException("implementation returned current curve");
				}

				// NOTE: Synchronization added to keep FindBugs™ happy
				lock (c)
				{
					c.coord = coord;
					c.endomorphism = endomorphism;
					c.multiplier = multiplier;
				}

				return c;
			}
		}

		protected internal FiniteField field;
		protected internal ECFieldElement a, b;
		protected internal BigInteger order, cofactor;

		protected internal int coord = COORD_AFFINE;
		protected internal ECEndomorphism endomorphism = null;
		protected internal ECMultiplier multiplier = null;

		public ECCurve(FiniteField field)
		{
			this.field = field;
		}

		public abstract int getFieldSize();

		public abstract ECFieldElement fromBigInteger(BigInteger x);

		public abstract bool isValidFieldElement(BigInteger x);

		public virtual Config configure()
		{
			lock (this)
			{
				return new Config(this, this.coord, this.endomorphism, this.multiplier);
			}
		}

		public virtual ECPoint validatePoint(BigInteger x, BigInteger y)
		{
			ECPoint p = createPoint(x, y);
			if (!p.isValid())
			{
				throw new IllegalArgumentException("Invalid point coordinates");
			}
			return p;
		}

		/// @deprecated per-point compression property will be removed, use <seealso cref="#validatePoint(BigInteger, BigInteger)"/>
		/// and refer <seealso cref="ECPoint#getEncoded(boolean)"/> 
		public virtual ECPoint validatePoint(BigInteger x, BigInteger y, bool withCompression)
		{
			ECPoint p = createPoint(x, y, withCompression);
			if (!p.isValid())
			{
				throw new IllegalArgumentException("Invalid point coordinates");
			}
			return p;
		}

		public virtual ECPoint createPoint(BigInteger x, BigInteger y)
		{
			return createPoint(x, y, false);
		}

		/// @deprecated per-point compression property will be removed, use <seealso cref="#createPoint(BigInteger, BigInteger)"/>
		/// and refer <seealso cref="ECPoint#getEncoded(boolean)"/> 
		public virtual ECPoint createPoint(BigInteger x, BigInteger y, bool withCompression)
		{
			return createRawPoint(fromBigInteger(x), fromBigInteger(y), withCompression);
		}

		public abstract ECCurve cloneCurve();

		public abstract ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression);

		public abstract ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression);

		public virtual ECMultiplier createDefaultMultiplier()
		{
			if (endomorphism is GLVEndomorphism)
			{
				return new GLVMultiplier(this, (GLVEndomorphism)endomorphism);
			}

			return new WNafL2RMultiplier();
		}

		public virtual bool supportsCoordinateSystem(int coord)
		{
			return coord == COORD_AFFINE;
		}

		public virtual PreCompInfo getPreCompInfo(ECPoint point, string name)
		{
			checkPoint(point);

			Hashtable table;
			lock (point)
			{
				table = point.preCompTable;
			}

			if (null == table)
			{
				return null;
			}

			lock (table)
			{
				return (PreCompInfo)table.get(name);
			}
		}

		/// <summary>
		/// Compute a <code>PreCompInfo</code> for a point on this curve, under a given name. Used by
		/// <code>ECMultiplier</code>s to save the precomputation for this <code>ECPoint</code> for use
		/// by subsequent multiplication.
		/// </summary>
		/// <param name="point">
		///            The <code>ECPoint</code> to store precomputations for. </param>
		/// <param name="name">
		///            A <code>String</code> used to index precomputations of different types. </param>
		/// <param name="callback">
		///            Called to calculate the <code>PreCompInfo</code>. </param>
		public virtual PreCompInfo precompute(ECPoint point, string name, PreCompCallback callback)
		{
			checkPoint(point);

			Hashtable table;
			lock (point)
			{
				table = point.preCompTable;
				if (null == table)
				{
					point.preCompTable = table = new Hashtable(4);
				}
			}

			lock (table)
			{
				PreCompInfo existing = (PreCompInfo)table.get(name);
				PreCompInfo result = callback.precompute(existing);

				if (result != existing)
				{
					table.put(name, result);
				}

				return result;
			}
		}

		public virtual ECPoint importPoint(ECPoint p)
		{
			if (this == p.getCurve())
			{
				return p;
			}
			if (p.isInfinity())
			{
				return getInfinity();
			}

			// TODO Default behaviour could be improved if the two curves have the same coordinate system by copying any Z coordinates.
			p = p.normalize();

			return createPoint(p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger(), p.withCompression);
		}

		/// <summary>
		/// Normalization ensures that any projective coordinate is 1, and therefore that the x, y
		/// coordinates reflect those of the equivalent point in an affine coordinate system. Where more
		/// than one point is to be normalized, this method will generally be more efficient than
		/// normalizing each point separately.
		/// </summary>
		/// <param name="points">
		///            An array of points that will be updated in place with their normalized versions,
		///            where necessary </param>
		public virtual void normalizeAll(ECPoint[] points)
		{
			normalizeAll(points, 0, points.Length, null);
		}

		/// <summary>
		/// Normalization ensures that any projective coordinate is 1, and therefore that the x, y
		/// coordinates reflect those of the equivalent point in an affine coordinate system. Where more
		/// than one point is to be normalized, this method will generally be more efficient than
		/// normalizing each point separately. An (optional) z-scaling factor can be applied; effectively
		/// each z coordinate is scaled by this value prior to normalization (but only one
		/// actual multiplication is needed).
		/// </summary>
		/// <param name="points">
		///            An array of points that will be updated in place with their normalized versions,
		///            where necessary </param>
		/// <param name="off">
		///            The start of the range of points to normalize </param>
		/// <param name="len">
		///            The length of the range of points to normalize </param>
		/// <param name="iso">
		///            The (optional) z-scaling factor - can be null </param>
		public virtual void normalizeAll(ECPoint[] points, int off, int len, ECFieldElement iso)
		{
			checkPoints(points, off, len);

			switch (this.getCoordinateSystem())
			{
			case ECCurve.COORD_AFFINE:
			case ECCurve.COORD_LAMBDA_AFFINE:
			{
				if (iso != null)
				{
					throw new IllegalArgumentException("'iso' not valid for affine coordinates");
				}
				return;
			}
			}

			/*
			 * Figure out which of the points actually need to be normalized
			 */
			ECFieldElement[] zs = new ECFieldElement[len];
			int[] indices = new int[len];
			int count = 0;
			for (int i = 0; i < len; ++i)
			{
				ECPoint p = points[off + i];
				if (null != p && (iso != null || !p.isNormalized()))
				{
					zs[count] = p.getZCoord(0);
					indices[count++] = off + i;
				}
			}

			if (count == 0)
			{
				return;
			}

			ECAlgorithms.montgomeryTrick(zs, 0, count, iso);

			for (int j = 0; j < count; ++j)
			{
				int index = indices[j];
				points[index] = points[index].normalize(zs[j]);
			}
		}

		public abstract ECPoint getInfinity();

		public virtual FiniteField getField()
		{
			return field;
		}

		public virtual ECFieldElement getA()
		{
			return a;
		}

		public virtual ECFieldElement getB()
		{
			return b;
		}

		public virtual BigInteger getOrder()
		{
			return order;
		}

		public virtual BigInteger getCofactor()
		{
			return cofactor;
		}

		public virtual int getCoordinateSystem()
		{
			return coord;
		}

		public abstract ECPoint decompressPoint(int yTilde, BigInteger X1);

		public virtual ECEndomorphism getEndomorphism()
		{
			return endomorphism;
		}

		/// <summary>
		/// Sets the default <code>ECMultiplier</code>, unless already set. 
		/// </summary>
		public virtual ECMultiplier getMultiplier()
		{
			lock (this)
			{
				if (this.multiplier == null)
				{
					this.multiplier = createDefaultMultiplier();
				}
				return this.multiplier;
			}
		}

		/// <summary>
		/// Decode a point on this curve from its ASN.1 encoding. The different
		/// encodings are taken account of, including point compression for
		/// <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17). </summary>
		/// <returns> The decoded point. </returns>
		public virtual ECPoint decodePoint(byte[] encoded)
		{
			ECPoint p = null;
			int expectedLength = (getFieldSize() + 7) / 8;

			byte type = encoded[0];
			switch (type)
			{
			case 0x00: // infinity
			{
				if (encoded.Length != 1)
				{
					throw new IllegalArgumentException("Incorrect length for infinity encoding");
				}

				p = getInfinity();
				break;
			}
			case 0x02: // compressed
			case 0x03: // compressed
			{
				if (encoded.Length != (expectedLength + 1))
				{
					throw new IllegalArgumentException("Incorrect length for compressed encoding");
				}

				int yTilde = type & 1;
				BigInteger X = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);

				p = decompressPoint(yTilde, X);
				if (!p.implIsValid(true, true))
				{
					throw new IllegalArgumentException("Invalid point");
				}

				break;
			}
			case 0x04: // uncompressed
			{
				if (encoded.Length != (2 * expectedLength + 1))
				{
					throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
				}

				BigInteger X = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);
				BigInteger Y = BigIntegers.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);

				p = validatePoint(X, Y);
				break;
			}
			case 0x06: // hybrid
			case 0x07: // hybrid
			{
				if (encoded.Length != (2 * expectedLength + 1))
				{
					throw new IllegalArgumentException("Incorrect length for hybrid encoding");
				}

				BigInteger X = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);
				BigInteger Y = BigIntegers.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);

				if (Y.testBit(0) != (type == 0x07))
				{
					throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding");
				}

				p = validatePoint(X, Y);
				break;
			}
			default:
				throw new IllegalArgumentException("Invalid point encoding 0x" + Convert.ToString(type, 16));
			}

			if (type != 0x00 && p.isInfinity())
			{
				throw new IllegalArgumentException("Invalid infinity encoding");
			}

			return p;
		}

		/// <summary>
		/// Create a cache-safe lookup table for the specified sequence of points. All the points MUST
		/// belong to this <seealso cref="ECCurve"/> instance, and MUST already be normalized.
		/// </summary>

		public virtual ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{

			int FE_BYTES = (int)((uint)(getFieldSize() + 7) >> 3);


			byte[] table = new byte[len * FE_BYTES * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					byte[] px = p.getRawXCoord().toBigInteger().toByteArray();
					byte[] py = p.getRawYCoord().toBigInteger().toByteArray();

					int pxStart = px.Length > FE_BYTES ? 1 : 0, pxLen = px.Length - pxStart;
					int pyStart = py.Length > FE_BYTES ? 1 : 0, pyLen = py.Length - pyStart;

					JavaSystem.arraycopy(px, pxStart, table, pos + FE_BYTES - pxLen, pxLen);
					pos += FE_BYTES;
					JavaSystem.arraycopy(py, pyStart, table, pos + FE_BYTES - pyLen, pyLen);
					pos += FE_BYTES;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_BYTES, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly ECCurve outerInstance;

			private int len;
			private int FE_BYTES;
			private byte[] table;

			public ECLookupTableAnonymousInnerClass(ECCurve outerInstance, int len, int FE_BYTES, byte[] table)
			{
				this.outerInstance = outerInstance;
				this.len = len;
				this.FE_BYTES = FE_BYTES;
				this.table = table;
			}

			public int getSize()
			{
				return len;
			}

			public ECPoint lookup(int index)
			{
				byte[] x = new byte[FE_BYTES], y = new byte[FE_BYTES];
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					int MASK = ((i ^ index) - 1) >> 31;

					for (int j = 0; j < FE_BYTES; ++j)
					{
						x[j] ^= (byte)(table[pos + j] & MASK);
						y[j] ^= (byte)(table[pos + FE_BYTES + j] & MASK);
					}

					pos += (FE_BYTES * 2);
				}

				return outerInstance.createRawPoint(outerInstance.fromBigInteger(new BigInteger(1, x)), outerInstance.fromBigInteger(new BigInteger(1, y)), false);
			}
		}

		public virtual void checkPoint(ECPoint point)
		{
			if (null == point || (this != point.getCurve()))
			{
				throw new IllegalArgumentException("'point' must be non-null and on this curve");
			}
		}

		public virtual void checkPoints(ECPoint[] points)
		{
			checkPoints(points, 0, points.Length);
		}

		public virtual void checkPoints(ECPoint[] points, int off, int len)
		{
			if (points == null)
			{
				throw new IllegalArgumentException("'points' cannot be null");
			}
			if (off < 0 || len < 0 || (off > (points.Length - len)))
			{
				throw new IllegalArgumentException("invalid range specified for 'points'");
			}

			for (int i = 0; i < len; ++i)
			{
				ECPoint point = points[off + i];
				if (null != point && this != point.getCurve())
				{
					throw new IllegalArgumentException("'points' entries must be null or on this curve");
				}
			}
		}

		public virtual bool Equals(ECCurve other)
		{
			return this == other || (null != other && getField().Equals(other.getField()) && getA().toBigInteger().Equals(other.getA().toBigInteger()) && getB().toBigInteger().Equals(other.getB().toBigInteger()));
		}

		public override bool Equals(object obj)
		{
			return this == obj || (obj is ECCurve && Equals((ECCurve)obj));
		}

		public override int GetHashCode()
		{
			return getField().GetHashCode() ^ Integers.rotateLeft(getA().toBigInteger().GetHashCode(), 8) ^ Integers.rotateLeft(getB().toBigInteger().GetHashCode(), 16);
		}

		public abstract class AbstractFp : ECCurve
		{
			public AbstractFp(BigInteger q) : base(FiniteFields.getPrimeField(q))
			{
			}

			public override bool isValidFieldElement(BigInteger x)
			{
				return x != null && x.signum() >= 0 && x.compareTo(this.getField().getCharacteristic()) < 0;
			}

			public override ECPoint decompressPoint(int yTilde, BigInteger X1)
			{
				ECFieldElement x = this.fromBigInteger(X1);
				ECFieldElement rhs = x.square().add(this.a).multiply(x).add(this.b);
				ECFieldElement y = rhs.sqrt();

				/*
				 * If y is not a square, then we haven't got a point on the curve
				 */
				if (y == null)
				{
					throw new IllegalArgumentException("Invalid point compression");
				}

				if (y.testBitZero() != (yTilde == 1))
				{
					// Use the other root
					y = y.negate();
				}

				return this.createRawPoint(x, y, true);
			}
		}

		/// <summary>
		/// Elliptic curve over Fp
		/// </summary>
		public class Fp : AbstractFp
		{
			internal const int FP_DEFAULT_COORDS = ECCurve.COORD_JACOBIAN_MODIFIED;

			internal BigInteger q, r;
			internal ECPoint.Fp infinity;

			/// @deprecated use constructor taking order/cofactor 
			public Fp(BigInteger q, BigInteger a, BigInteger b) : this(q, a, b, null, null)
			{
			}

			public Fp(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) : base(q)
			{

				this.q = q;
				this.r = ECFieldElement.Fp.calculateResidue(q);
				this.infinity = new ECPoint.Fp(this, null, null, false);

				this.a = fromBigInteger(a);
				this.b = fromBigInteger(b);
				this.order = order;
				this.cofactor = cofactor;
				this.coord = FP_DEFAULT_COORDS;
			}

			/// @deprecated use constructor taking order/cofactor 
			public Fp(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b) : this(q, r, a, b, null, null)
			{
			}

			public Fp(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor) : base(q)
			{

				this.q = q;
				this.r = r;
				this.infinity = new ECPoint.Fp(this, null, null, false);

				this.a = a;
				this.b = b;
				this.order = order;
				this.cofactor = cofactor;
				this.coord = FP_DEFAULT_COORDS;
			}

			public override ECCurve cloneCurve()
			{
				return new Fp(this.q, this.r, this.a, this.b, this.order, this.cofactor);
			}

			public override bool supportsCoordinateSystem(int coord)
			{
				switch (coord)
				{
				case ECCurve.COORD_AFFINE:
				case ECCurve.COORD_HOMOGENEOUS:
				case ECCurve.COORD_JACOBIAN:
				case ECCurve.COORD_JACOBIAN_MODIFIED:
					return true;
				default:
					return false;
				}
			}

			public virtual BigInteger getQ()
			{
				return q;
			}

			public override int getFieldSize()
			{
				return q.bitLength();
			}

			public override ECFieldElement fromBigInteger(BigInteger x)
			{
				return new ECFieldElement.Fp(this.q, this.r, x);
			}

			public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
			{
				return new ECPoint.Fp(this, x, y, withCompression);
			}

			public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
			{
				return new ECPoint.Fp(this, x, y, zs, withCompression);
			}

			public override ECPoint importPoint(ECPoint p)
			{
				if (this != p.getCurve() && this.getCoordinateSystem() == ECCurve.COORD_JACOBIAN && !p.isInfinity())
				{
					switch (p.getCurve().getCoordinateSystem())
					{
					case ECCurve.COORD_JACOBIAN:
					case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
					case ECCurve.COORD_JACOBIAN_MODIFIED:
						return new ECPoint.Fp(this, fromBigInteger(p.x.toBigInteger()), fromBigInteger(p.y.toBigInteger()), new ECFieldElement[]{fromBigInteger(p.zs[0].toBigInteger())}, p.withCompression);
					default:
						break;
					}
				}

				return base.importPoint(p);
			}

			public override ECPoint getInfinity()
			{
				return infinity;
			}
		}

		public abstract class AbstractF2m : ECCurve
		{
			public static BigInteger inverse(int m, int[] ks, BigInteger x)
			{
				return (new LongArray(x)).modInverse(m, ks).toBigInteger();
			}

			/// <summary>
			/// The auxiliary values <code>s<sub>0</sub></code> and
			/// <code>s<sub>1</sub></code> used for partial modular reduction for
			/// Koblitz curves.
			/// </summary>
			internal BigInteger[] si = null;

			internal static FiniteField buildField(int m, int k1, int k2, int k3)
			{
				if (k1 == 0)
				{
					throw new IllegalArgumentException("k1 must be > 0");
				}

				if (k2 == 0)
				{
					if (k3 != 0)
					{
						throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
					}

					return FiniteFields.getBinaryExtensionField(new int[]{0, k1, m});
				}

				if (k2 <= k1)
				{
					throw new IllegalArgumentException("k2 must be > k1");
				}

				if (k3 <= k2)
				{
					throw new IllegalArgumentException("k3 must be > k2");
				}

				return FiniteFields.getBinaryExtensionField(new int[]{0, k1, k2, k3, m});
			}

			public AbstractF2m(int m, int k1, int k2, int k3) : base(buildField(m, k1, k2, k3))
			{
			}

			public override bool isValidFieldElement(BigInteger x)
			{
				return x != null && x.signum() >= 0 && x.bitLength() <= this.getFieldSize();
			}

			public override ECPoint createPoint(BigInteger x, BigInteger y, bool withCompression)
			{
				ECFieldElement X = this.fromBigInteger(x), Y = this.fromBigInteger(y);

				int coord = this.getCoordinateSystem();

				switch (coord)
				{
				case ECCurve.COORD_LAMBDA_AFFINE:
				case ECCurve.COORD_LAMBDA_PROJECTIVE:
				{
					if (X.isZero())
					{
						if (!Y.square().Equals(this.getB()))
						{
							throw new IllegalArgumentException();
						}
					}
					/*
					 * NOTE: A division could be avoided using a projective result, except at present
					 * callers will expect that the result is already normalized.
					 */
	//                else if (coord == COORD_LAMBDA_PROJECTIVE)
	//                {
	//                    ECFieldElement Z = X;
	//                    X = X.square();
	//                    Y = Y.add(X);
	//                    return createRawPoint(X, Y, new ECFieldElement[]{ Z }, withCompression);
	//                }
					else
					{
						// Y becomes Lambda (X + Y/X) here
						Y = Y.divide(X).add(X);
					}
					break;
				}
				default:
				{
					break;
				}
				}

				return this.createRawPoint(X, Y, withCompression);
			}

			/// <summary>
			/// Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
			/// </summary>
			/// <param name="yTilde">
			///            ~yp, an indication bit for the decompression of yp. </param>
			/// <param name="X1">
			///            The field element xp. </param>
			/// <returns> the decompressed point. </returns>
			public override ECPoint decompressPoint(int yTilde, BigInteger X1)
			{
				ECFieldElement x = this.fromBigInteger(X1), y = null;
				if (x.isZero())
				{
					y = this.getB().sqrt();
				}
				else
				{
					ECFieldElement beta = x.square().invert().multiply(this.getB()).add(this.getA()).add(x);
					ECFieldElement z = solveQuadraticEquation(beta);
					if (z != null)
					{
						if (z.testBitZero() != (yTilde == 1))
						{
							z = z.addOne();
						}

						switch (this.getCoordinateSystem())
						{
						case ECCurve.COORD_LAMBDA_AFFINE:
						case ECCurve.COORD_LAMBDA_PROJECTIVE:
						{
							y = z.add(x);
							break;
						}
						default:
						{
							y = z.multiply(x);
							break;
						}
						}
					}
				}

				if (y == null)
				{
					throw new IllegalArgumentException("Invalid point compression");
				}

				return this.createRawPoint(x, y, true);
			}

			/// <summary>
			/// Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
			/// D.1.6) The other solution is <code>z + 1</code>.
			/// </summary>
			/// <param name="beta">
			///            The value to solve the quadratic equation for. </param>
			/// <returns> the solution for <code>z<sup>2</sup> + z = beta</code> or
			///         <code>null</code> if no solution exists. </returns>
			public virtual ECFieldElement solveQuadraticEquation(ECFieldElement beta)
			{
				if (beta.isZero())
				{
					return beta;
				}

				ECFieldElement gamma, z, zeroElement = this.fromBigInteger(ECConstants_Fields.ZERO);

				int m = this.getFieldSize();
				Random rand = new Random();
				do
				{
					ECFieldElement t = this.fromBigInteger(new BigInteger(m, rand));
					z = zeroElement;
					ECFieldElement w = beta;
					for (int i = 1; i < m; i++)
					{
						ECFieldElement w2 = w.square();
						z = z.square().add(w2.multiply(t));
						w = w2.add(beta);
					}
					if (!w.isZero())
					{
						return null;
					}
					gamma = z.square().add(z);
				} while (gamma.isZero());

				return z;
			}

			/// <returns> the auxiliary values <code>s<sub>0</sub></code> and
			/// <code>s<sub>1</sub></code> used for partial modular reduction for
			/// Koblitz curves. </returns>
			public virtual BigInteger[] getSi()
			{
				lock (this)
				{
					if (si == null)
					{
						si = Tnaf.getSi(this);
					}
					return si;
				}
			}

			/// <summary>
			/// Returns true if this is a Koblitz curve (ABC curve). </summary>
			/// <returns> true if this is a Koblitz curve (ABC curve), false otherwise </returns>
			public virtual bool isKoblitz()
			{
				return this.order != null && this.cofactor != null && this.b.isOne() && (this.a.isZero() || this.a.isOne());
			}
		}

		/// <summary>
		/// Elliptic curves over F2m. The Weierstrass equation is given by
		/// <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
		/// </summary>
		public class F2m : AbstractF2m
		{
			internal const int F2M_DEFAULT_COORDS = ECCurve.COORD_LAMBDA_PROJECTIVE;

			/// <summary>
			/// The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
			/// </summary>
			internal int m; // can't be final - JDK 1.1

			/// <summary>
			/// TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
			/// x<sup>k</sup> + 1</code> represents the reduction polynomial
			/// <code>f(z)</code>.<br>
			/// PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br>
			/// </summary>
			internal int k1; // can't be final - JDK 1.1

			/// <summary>
			/// TPB: Always set to <code>0</code><br>
			/// PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br>
			/// </summary>
			internal int k2; // can't be final - JDK 1.1

			/// <summary>
			/// TPB: Always set to <code>0</code><br>
			/// PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
			/// x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
			/// represents the reduction polynomial <code>f(z)</code>.<br>
			/// </summary>
			internal int k3; // can't be final - JDK 1.1

			 /// <summary>
			 /// The point at infinity on this curve.
			 /// </summary>
			internal ECPoint.F2m infinity; // can't be final - JDK 1.1

			/// <summary>
			/// Constructor for Trinomial Polynomial Basis (TPB). </summary>
			/// <param name="m">  The exponent <code>m</code> of
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="k"> The integer <code>k</code> where <code>x<sup>m</sup> +
			/// x<sup>k</sup> + 1</code> represents the reduction
			/// polynomial <code>f(z)</code>. </param>
			/// <param name="a"> The coefficient <code>a</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="b"> The coefficient <code>b</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// @deprecated use constructor taking order/cofactor 
			public F2m(int m, int k, BigInteger a, BigInteger b) : this(m, k, 0, 0, a, b, null, null)
			{
			}

			/// <summary>
			/// Constructor for Trinomial Polynomial Basis (TPB). </summary>
			/// <param name="m">  The exponent <code>m</code> of
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="k"> The integer <code>k</code> where <code>x<sup>m</sup> +
			/// x<sup>k</sup> + 1</code> represents the reduction
			/// polynomial <code>f(z)</code>. </param>
			/// <param name="a"> The coefficient <code>a</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="b"> The coefficient <code>b</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="order"> The order of the main subgroup of the elliptic curve. </param>
			/// <param name="cofactor"> The cofactor of the elliptic curve, i.e.
			/// <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>. </param>
			public F2m(int m, int k, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) : this(m, k, 0, 0, a, b, order, cofactor)
			{
			}

			/// <summary>
			/// Constructor for Pentanomial Polynomial Basis (PPB). </summary>
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
			/// <param name="a"> The coefficient <code>a</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="b"> The coefficient <code>b</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// @deprecated use constructor taking order/cofactor 
			public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b) : this(m, k1, k2, k3, a, b, null, null)
			{
			}

			/// <summary>
			/// Constructor for Pentanomial Polynomial Basis (PPB). </summary>
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
			/// <param name="a"> The coefficient <code>a</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="b"> The coefficient <code>b</code> in the Weierstrass equation
			/// for non-supersingular elliptic curves over
			/// <code>F<sub>2<sup>m</sup></sub></code>. </param>
			/// <param name="order"> The order of the main subgroup of the elliptic curve. </param>
			/// <param name="cofactor"> The cofactor of the elliptic curve, i.e.
			/// <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>. </param>
			public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) : base(m, k1, k2, k3)
			{

				this.m = m;
				this.k1 = k1;
				this.k2 = k2;
				this.k3 = k3;
				this.order = order;
				this.cofactor = cofactor;

				this.infinity = new ECPoint.F2m(this, null, null, false);
				this.a = fromBigInteger(a);
				this.b = fromBigInteger(b);
				this.coord = F2M_DEFAULT_COORDS;
			}

			public F2m(int m, int k1, int k2, int k3, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor) : base(m, k1, k2, k3)
			{

				this.m = m;
				this.k1 = k1;
				this.k2 = k2;
				this.k3 = k3;
				this.order = order;
				this.cofactor = cofactor;

				this.infinity = new ECPoint.F2m(this, null, null, false);
				this.a = a;
				this.b = b;
				this.coord = F2M_DEFAULT_COORDS;
			}

			public override ECCurve cloneCurve()
			{
				return new F2m(this.m, this.k1, this.k2, this.k3, this.a, this.b, this.order, this.cofactor);
			}

			public override bool supportsCoordinateSystem(int coord)
			{
				switch (coord)
				{
				case ECCurve.COORD_AFFINE:
				case ECCurve.COORD_HOMOGENEOUS:
				case ECCurve.COORD_LAMBDA_PROJECTIVE:
					return true;
				default:
					return false;
				}
			}

			public override ECMultiplier createDefaultMultiplier()
			{
				if (isKoblitz())
				{
					return new WTauNafMultiplier();
				}

				return base.createDefaultMultiplier();
			}

			public override int getFieldSize()
			{
				return m;
			}

			public override ECFieldElement fromBigInteger(BigInteger x)
			{
				return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, x);
			}

			public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
			{
				return new ECPoint.F2m(this, x, y, withCompression);
			}

			public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
			{
				return new ECPoint.F2m(this, x, y, zs, withCompression);
			}

			public override ECPoint getInfinity()
			{
				return infinity;
			}

			public virtual int getM()
			{
				return m;
			}

			/// <summary>
			/// Return true if curve uses a Trinomial basis.
			/// </summary>
			/// <returns> true if curve Trinomial, false otherwise. </returns>
			public virtual bool isTrinomial()
			{
				return k2 == 0 && k3 == 0;
			}

			public virtual int getK1()
			{
				return k1;
			}

			public virtual int getK2()
			{
				return k2;
			}

			public virtual int getK3()
			{
				return k3;
			}


			public override ec.ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
			{

				int FE_LONGS = (int)((uint)(m + 63) >> 6);

				int[] ks = isTrinomial() ? new int[]{k1} : new int[]{k1, k2, k3};


				ulong[] table = new ulong[len * FE_LONGS * 2];
				{
					int pos = 0;
					for (int i = 0; i < len; ++i)
					{
						ECPoint p = points[off + i];
						((ECFieldElement.F2m)p.getRawXCoord()).x.copyTo(table, pos);
						pos += FE_LONGS;
						((ECFieldElement.F2m)p.getRawYCoord()).x.copyTo(table, pos);
						pos += FE_LONGS;
					}
				}

				return new ECLookupTable(this, len, FE_LONGS, ks, table);
			}

			public class ECLookupTable : ec.ECLookupTable
			{
				private readonly F2m outerInstance;

				private int len;
				private int FE_LONGS;
				private int[] ks;
				private ulong[] table;

				public ECLookupTable(F2m outerInstance, int len, int FE_LONGS, int[] ks, ulong[] table)
				{
					this.outerInstance = outerInstance;
					this.len = len;
					this.FE_LONGS = FE_LONGS;
					this.ks = ks;
					this.table = table;
				}

				public int getSize()
				{
					return len;
				}

				public ECPoint lookup(int index)
				{
					ulong[] x = Nat.create64(FE_LONGS), y = Nat.create64(FE_LONGS);
					int pos = 0;

					for (int i = 0; i < len; ++i)
					{
						ulong MASK = (ulong)(((i ^ index) - 1) >> 31);

						for (int j = 0; j < FE_LONGS; ++j)
						{
							x[j] ^= table[pos + j] & MASK;
							y[j] ^= table[pos + FE_LONGS + j] & MASK;
						}

						pos += (FE_LONGS * 2);
					}

					return outerInstance.createRawPoint(new ECFieldElement.F2m(outerInstance.m, ks, new LongArray(x)), new ECFieldElement.F2m(outerInstance.m, ks, new LongArray(y)), false);
				}
			}
		}
	}

}