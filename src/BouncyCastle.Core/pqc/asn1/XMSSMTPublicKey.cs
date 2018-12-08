using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.asn1
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// XMSSMTPublicKey
	/// <pre>
	///     XMSSMTPublicKey ::= SEQUENCE {
	///         version       INTEGER -- 0
	///         publicSeed    OCTET STRING
	///         root          OCTET STRING
	///    }
	/// </pre>
	/// </summary>
	public class XMSSMTPublicKey : ASN1Object
	{
		private readonly byte[] publicSeed;
		private readonly byte[] root;

		public XMSSMTPublicKey(byte[] publicSeed, byte[] root)
		{
			this.publicSeed = Arrays.clone(publicSeed);
			this.root = Arrays.clone(root);
		}

		private XMSSMTPublicKey(ASN1Sequence seq)
		{
			if (!ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().Equals(BigInteger.valueOf(0)))
			{
				throw new IllegalArgumentException("unknown version of sequence");
			}

			this.publicSeed = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(1)).getOctets());
			this.root = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(2)).getOctets());
		}

		public static XMSSMTPublicKey getInstance(object o)
		{
			if (o is XMSSMTPublicKey)
			{
				return (XMSSMTPublicKey)o;
			}
			else if (o != null)
			{
				return new XMSSMTPublicKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual byte[] getPublicSeed()
		{
			return Arrays.clone(publicSeed);
		}

		public virtual byte[] getRoot()
		{
			return Arrays.clone(root);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(0)); // version

			v.add(new DEROctetString(publicSeed));
			v.add(new DEROctetString(root));

			return new DERSequence(v);
		}
	}

}