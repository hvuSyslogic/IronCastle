using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.sec
{

	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// the elliptic curve private key object from SEC 1
	/// </summary>
	public class ECPrivateKey : ASN1Object
	{
		private ASN1Sequence seq;

		private ECPrivateKey(ASN1Sequence seq)
		{
			this.seq = seq;
		}

		public static ECPrivateKey getInstance(object obj)
		{
			if (obj is ECPrivateKey)
			{
				return (ECPrivateKey)obj;
			}

			if (obj != null)
			{
				return new ECPrivateKey(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// @deprecated use constructor which takes orderBitLength to guarantee correct encoding. 
		public ECPrivateKey(BigInteger key) : this(key.bitLength(), key)
		{
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="orderBitLength"> the bitLength of the order of the curve. </param>
		/// <param name="key"> the private key value. </param>
		public ECPrivateKey(int orderBitLength, BigInteger key)
		{
			byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(1));
			v.add(new DEROctetString(bytes));

			seq = new DERSequence(v);
		}

		/// @deprecated use constructor which takes orderBitLength to guarantee correct encoding. 
		public ECPrivateKey(BigInteger key, ASN1Encodable parameters) : this(key, null, parameters)
		{
		}

		/// @deprecated use constructor which takes orderBitLength to guarantee correct encoding. 
		public ECPrivateKey(BigInteger key, DERBitString publicKey, ASN1Encodable parameters) : this(key.bitLength(), key, publicKey, parameters)
		{
		}

		public ECPrivateKey(int orderBitLength, BigInteger key, ASN1Encodable parameters) : this(orderBitLength, key, null, parameters)
		{
		}

		public ECPrivateKey(int orderBitLength, BigInteger key, DERBitString publicKey, ASN1Encodable parameters)
		{
			byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(1));
			v.add(new DEROctetString(bytes));

			if (parameters != null)
			{
				v.add(new DERTaggedObject(true, 0, parameters));
			}

			if (publicKey != null)
			{
				v.add(new DERTaggedObject(true, 1, publicKey));
			}

			seq = new DERSequence(v);
		}

		public virtual BigInteger getKey()
		{
			ASN1OctetString octs = (ASN1OctetString)seq.getObjectAt(1);

			return new BigInteger(1, octs.getOctets());
		}

		public virtual DERBitString getPublicKey()
		{
			return (DERBitString)getObjectInTag(1);
		}

		public virtual ASN1Primitive getParameters()
		{
			return getObjectInTag(0);
		}

		private ASN1Primitive getObjectInTag(int tagNo)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1Encodable obj = (ASN1Encodable)e.nextElement();

				if (obj is ASN1TaggedObject)
				{
					ASN1TaggedObject tag = (ASN1TaggedObject)obj;
					if (tag.getTagNo() == tagNo)
					{
						return tag.getObject().toASN1Primitive();
					}
				}
			}
			return null;
		}

		/// <summary>
		/// ECPrivateKey ::= SEQUENCE {
		///     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
		///     privateKey OCTET STRING,
		///     parameters [0] Parameters OPTIONAL,
		///     publicKey [1] BIT STRING OPTIONAL }
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}