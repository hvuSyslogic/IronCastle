using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.sec
{

	
	/// <summary>
	/// the elliptic curve private key object from SEC 1 </summary>
	/// @deprecated use ECPrivateKey 
	public class ECPrivateKeyStructure : ASN1Object
	{
		private ASN1Sequence seq;

		public ECPrivateKeyStructure(ASN1Sequence seq)
		{
			this.seq = seq;
		}

		public ECPrivateKeyStructure(BigInteger key)
		{
			byte[] bytes = BigIntegers.asUnsignedByteArray(key);

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(1));
			v.add(new DEROctetString(bytes));

			seq = new DERSequence(v);
		}

		public ECPrivateKeyStructure(BigInteger key, ASN1Encodable parameters) : this(key, null, parameters)
		{
		}

		public ECPrivateKeyStructure(BigInteger key, DERBitString publicKey, ASN1Encodable parameters)
		{
			byte[] bytes = BigIntegers.asUnsignedByteArray(key);

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
						return ((ASN1Encodable)tag.getObject()).toASN1Primitive();
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