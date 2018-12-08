using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.asn1
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GF2mField = org.bouncycastle.pqc.math.linearalgebra.GF2mField;
	using Permutation = org.bouncycastle.pqc.math.linearalgebra.Permutation;
	using PolynomialGF2mSmallM = org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

	/// <summary>
	/// Return the keyData to encode in the PrivateKeyInfo structure.
	/// <para>
	/// The ASN.1 definition of the key structure is
	/// </para>
	/// <pre>
	///   McElieceCCA2PrivateKey ::= SEQUENCE {
	///     m             INTEGER                  -- extension degree of the field
	///     k             INTEGER                  -- dimension of the code
	///     field         OCTET STRING             -- field polynomial
	///     goppaPoly     OCTET STRING             -- irreducible Goppa polynomial
	///     p             OCTET STRING             -- permutation vector
	///     digest        AlgorithmIdentifier      -- algorithm identifier for CCA2 digest
	///   }
	/// </pre>
	/// </summary>
	public class McElieceCCA2PrivateKey : ASN1Object
	{
		private int n;
		private int k;
		private byte[] encField;
		private byte[] encGp;
		private byte[] encP;
		private AlgorithmIdentifier digest;


		public McElieceCCA2PrivateKey(int n, int k, GF2mField field, PolynomialGF2mSmallM goppaPoly, Permutation p, AlgorithmIdentifier digest)
		{
			this.n = n;
			this.k = k;
			this.encField = field.getEncoded();
			this.encGp = goppaPoly.getEncoded();
			this.encP = p.getEncoded();
			this.digest = digest;
		}

		private McElieceCCA2PrivateKey(ASN1Sequence seq)
		{
			BigInteger bigN = ((ASN1Integer)seq.getObjectAt(0)).getValue();
			n = bigN.intValue();

			BigInteger bigK = ((ASN1Integer)seq.getObjectAt(1)).getValue();
			k = bigK.intValue();

			encField = ((ASN1OctetString)seq.getObjectAt(2)).getOctets();

			encGp = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

			encP = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

			digest = AlgorithmIdentifier.getInstance(seq.getObjectAt(5));
		}

		public virtual int getN()
		{
			return n;
		}

		public virtual int getK()
		{
			return k;
		}

		public virtual GF2mField getField()
		{
			return new GF2mField(encField);
		}

		public virtual PolynomialGF2mSmallM getGoppaPoly()
		{
			return new PolynomialGF2mSmallM(this.getField(), encGp);
		}

		public virtual Permutation getP()
		{
			return new Permutation(encP);
		}

		public virtual AlgorithmIdentifier getDigest()
		{
			return digest;
		}

		public override ASN1Primitive toASN1Primitive()
		{

			ASN1EncodableVector v = new ASN1EncodableVector();

			// encode <n>
			v.add(new ASN1Integer(n));

			// encode <k>
			v.add(new ASN1Integer(k));

			// encode <field>
			v.add(new DEROctetString(encField));

			// encode <gp>
			v.add(new DEROctetString(encGp));

			// encode <p>
			v.add(new DEROctetString(encP));

			v.add(digest);

			return new DERSequence(v);
		}

		public static McElieceCCA2PrivateKey getInstance(object o)
		{
			if (o is McElieceCCA2PrivateKey)
			{
				return (McElieceCCA2PrivateKey)o;
			}
			else if (o != null)
			{
				return new McElieceCCA2PrivateKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}
	}

}