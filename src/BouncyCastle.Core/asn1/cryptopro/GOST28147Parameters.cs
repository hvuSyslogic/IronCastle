using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cryptopro
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ASN.1 algorithm identifier parameters for GOST-28147
	/// </summary>
	public class GOST28147Parameters : ASN1Object
	{
		private ASN1OctetString iv;
		private ASN1ObjectIdentifier paramSet;

		public static GOST28147Parameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static GOST28147Parameters getInstance(object obj)
		{
			if (obj is GOST28147Parameters)
			{
				return (GOST28147Parameters)obj;
			}

			if (obj != null)
			{
				return new GOST28147Parameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public GOST28147Parameters(byte[] iv, ASN1ObjectIdentifier paramSet)
		{
			this.iv = new DEROctetString(iv);
			this.paramSet = paramSet;
		}

		private GOST28147Parameters(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			iv = (ASN1OctetString)e.nextElement();
			paramSet = (ASN1ObjectIdentifier)e.nextElement();
		}

		/// <summary>
		/// <pre>
		/// Gost28147-89-Parameters ::=
		///               SEQUENCE {
		///                       iv                   Gost28147-89-IV,
		///                       encryptionParamSet   OBJECT IDENTIFIER
		///                }
		/// 
		///   Gost28147-89-IV ::= OCTET STRING (SIZE (8))
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(iv);
			v.add(paramSet);

			return new DERSequence(v);
		}

		/// <summary>
		/// Return the OID representing the sBox to use.
		/// </summary>
		/// <returns> the sBox OID. </returns>
		public virtual ASN1ObjectIdentifier getEncryptionParamSet()
		{
			return paramSet;
		}

		/// <summary>
		/// Return the initialisation vector to use.
		/// </summary>
		/// <returns> the IV. </returns>
		public virtual byte[] getIV()
		{
			return Arrays.clone(iv.getOctets());
		}
	}

}