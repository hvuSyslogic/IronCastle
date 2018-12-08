using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{


	public class RSAPublicKey : ASN1Object
	{
		private BigInteger modulus;
		private BigInteger publicExponent;

		public static RSAPublicKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static RSAPublicKey getInstance(object obj)
		{
			if (obj is RSAPublicKey)
			{
				return (RSAPublicKey)obj;
			}

			if (obj != null)
			{
				return new RSAPublicKey(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public RSAPublicKey(BigInteger modulus, BigInteger publicExponent)
		{
			this.modulus = modulus;
			this.publicExponent = publicExponent;
		}

		private RSAPublicKey(ASN1Sequence seq)
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