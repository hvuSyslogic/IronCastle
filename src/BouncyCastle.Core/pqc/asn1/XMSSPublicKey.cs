﻿using BouncyCastle.Core.Port;
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
	/// XMSSPublicKey
	/// <pre>
	///     XMSSPublicKey ::= SEQUENCE {
	///         version       INTEGER -- 0
	///         publicSeed    OCTET STRING
	///         root          OCTET STRING
	///    }
	/// </pre>
	/// </summary>
	public class XMSSPublicKey : ASN1Object
	{
		private readonly byte[] publicSeed;
		private readonly byte[] root;

		public XMSSPublicKey(byte[] publicSeed, byte[] root)
		{
			this.publicSeed = Arrays.clone(publicSeed);
			this.root = Arrays.clone(root);
		}

		private XMSSPublicKey(ASN1Sequence seq)
		{
			if (!ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().Equals(BigInteger.valueOf(0)))
			{
				throw new IllegalArgumentException("unknown version of sequence");
			}

			this.publicSeed = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(1)).getOctets());
			this.root = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(2)).getOctets());
		}

		public static XMSSPublicKey getInstance(object o)
		{
			if (o is XMSSPublicKey)
			{
				return (XMSSPublicKey)o;
			}
			else if (o != null)
			{
				return new XMSSPublicKey(ASN1Sequence.getInstance(o));
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