using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x9
{

	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using PolynomialExtensionField = org.bouncycastle.math.field.PolynomialExtensionField;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ASN.1 def for Elliptic-Curve ECParameters structure. See
	/// X9.62, for further details.
	/// </summary>
	public class X9ECParameters : ASN1Object, X9ObjectIdentifiers
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private X9FieldID fieldID;
		private ECCurve curve;
		private X9ECPoint g;
		private BigInteger n;
		private BigInteger h;
		private byte[] seed;

		private X9ECParameters(ASN1Sequence seq)
		{
			if (!(seq.getObjectAt(0) is ASN1Integer) || !((ASN1Integer)seq.getObjectAt(0)).getValue().Equals(ONE))
			{
				throw new IllegalArgumentException("bad version in X9ECParameters");
			}

			this.n = ((ASN1Integer)seq.getObjectAt(4)).getValue();

			if (seq.size() == 6)
			{
				this.h = ((ASN1Integer)seq.getObjectAt(5)).getValue();
			}

			X9Curve x9c = new X9Curve(X9FieldID.getInstance(seq.getObjectAt(1)), n, h, ASN1Sequence.getInstance(seq.getObjectAt(2)));

			this.curve = x9c.getCurve();
			object p = seq.getObjectAt(3);

			if (p is X9ECPoint)
			{
				this.g = (X9ECPoint)p;
			}
			else
			{
				this.g = new X9ECPoint(curve, (ASN1OctetString)p);
			}

			this.seed = x9c.getSeed();
		}

		public static X9ECParameters getInstance(object obj)
		{
			if (obj is X9ECParameters)
			{
				return (X9ECParameters)obj;
			}

			if (obj != null)
			{
				return new X9ECParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n) : this(curve, g, n, null, null)
		{
		}

		public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n, BigInteger h) : this(curve, g, n, h, null)
		{
		}

		public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h) : this(curve, g, n, h, null)
		{
		}

		public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h, byte[] seed) : this(curve, new X9ECPoint(g), n, h, seed)
		{
		}

		public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n, BigInteger h, byte[] seed)
		{
			this.curve = curve;
			this.g = g;
			this.n = n;
			this.h = h;
			this.seed = Arrays.clone(seed);

			if (ECAlgorithms.isFpCurve(curve))
			{
				this.fieldID = new X9FieldID(curve.getField().getCharacteristic());
			}
			else if (ECAlgorithms.isF2mCurve(curve))
			{
				PolynomialExtensionField field = (PolynomialExtensionField)curve.getField();
				int[] exponents = field.getMinimalPolynomial().getExponentsPresent();
				if (exponents.Length == 3)
				{
					this.fieldID = new X9FieldID(exponents[2], exponents[1]);
				}
				else if (exponents.Length == 5)
				{
					this.fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
				}
				else
				{
					throw new IllegalArgumentException("Only trinomial and pentomial curves are supported");
				}
			}
			else
			{
				throw new IllegalArgumentException("'curve' is of an unsupported type");
			}
		}

		public virtual ECCurve getCurve()
		{
			return curve;
		}

		public virtual ECPoint getG()
		{
			return g.getPoint();
		}

		public virtual BigInteger getN()
		{
			return n;
		}

		public virtual BigInteger getH()
		{
			return h;
		}

		public virtual byte[] getSeed()
		{
			return Arrays.clone(seed);
		}

		/// <summary>
		/// Return the ASN.1 entry representing the Curve.
		/// </summary>
		/// <returns> the X9Curve for the curve in these parameters. </returns>
		public virtual X9Curve getCurveEntry()
		{
			return new X9Curve(curve, seed);
		}

		/// <summary>
		/// Return the ASN.1 entry representing the FieldID.
		/// </summary>
		/// <returns> the X9FieldID for the FieldID in these parameters. </returns>
		public virtual X9FieldID getFieldIDEntry()
		{
			return fieldID;
		}

		/// <summary>
		/// Return the ASN.1 entry representing the base point G.
		/// </summary>
		/// <returns> the X9ECPoint for the base point in these parameters. </returns>
		public virtual X9ECPoint getBaseEntry()
		{
			return g;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  ECParameters ::= SEQUENCE {
		///      version         INTEGER { ecpVer1(1) } (ecpVer1),
		///      fieldID         FieldID {{FieldTypes}},
		///      curve           X9Curve,
		///      base            X9ECPoint,
		///      order           INTEGER,
		///      cofactor        INTEGER OPTIONAL
		///  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(ONE));
			v.add(fieldID);
			v.add(new X9Curve(curve, seed));
			v.add(g);
			v.add(new ASN1Integer(n));

			if (h != null)
			{
				v.add(new ASN1Integer(h));
			}

			return new DERSequence(v);
		}
	}

}