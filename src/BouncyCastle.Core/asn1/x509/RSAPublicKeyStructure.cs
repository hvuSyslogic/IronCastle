using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// @deprecated use org.bouncycastle.asn1.pkcs.RSAPublicKey 
	public class RSAPublicKeyStructure : ASN1Object
	{
		private BigInteger modulus;
		private BigInteger publicExponent;

		public static RSAPublicKeyStructure getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static RSAPublicKeyStructure getInstance(object obj)
		{
			if (obj == null || obj is RSAPublicKeyStructure)
			{
				return (RSAPublicKeyStructure)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new RSAPublicKeyStructure((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid RSAPublicKeyStructure: " + obj.GetType().getName());
		}

		public RSAPublicKeyStructure(BigInteger modulus, BigInteger publicExponent)
		{
			this.modulus = modulus;
			this.publicExponent = publicExponent;
		}

		public RSAPublicKeyStructure(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			modulus = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
			publicExponent = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
		}

		public virtual BigInteger getModulus()
		{
			return modulus;
		}

		public virtual BigInteger getPublicExponent()
		{
			return publicExponent;
		}

		/// <summary>
		/// This outputs the key in PKCS1v2 format.
		/// <pre>
		///      RSAPublicKey ::= SEQUENCE {
		///                          modulus INTEGER, -- n
		///                          publicExponent INTEGER, -- e
		///                      }
		/// </pre>
		/// <para>
		/// </para>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(getModulus()));
			v.add(new ASN1Integer(getPublicExponent()));

			return new DERSequence(v);
		}
	}

}