using org.bouncycastle.util;

namespace org.bouncycastle.asn1.bc
{
	
	/// <summary>
	/// <pre>
	///     SecretKeyData ::= SEQUENCE {
	///         keyAlgorithm OBJECT IDENTIFIER,
	///         keyBytes OCTET STRING
	///     }
	/// </pre>
	/// </summary>
	public class SecretKeyData : ASN1Object
	{
		private readonly ASN1ObjectIdentifier keyAlgorithm;
		private readonly ASN1OctetString keyBytes;

		public SecretKeyData(ASN1ObjectIdentifier keyAlgorithm, byte[] keyBytes)
		{
			this.keyAlgorithm = keyAlgorithm;
			this.keyBytes = new DEROctetString(Arrays.clone(keyBytes));
		}

		private SecretKeyData(ASN1Sequence seq)
		{
			this.keyAlgorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			this.keyBytes = ASN1OctetString.getInstance(seq.getObjectAt(1));
		}

		public static SecretKeyData getInstance(object o)
		{
			if (o is SecretKeyData)
			{
				return (SecretKeyData)o;
			}
			else if (o != null)
			{
				return new SecretKeyData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual byte[] getKeyBytes()
		{
			return Arrays.clone(keyBytes.getOctets());
		}

		public virtual ASN1ObjectIdentifier getKeyAlgorithm()
		{
			return keyAlgorithm;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyAlgorithm);
			v.add(keyBytes);

			return new DERSequence(v);
		}
	}

}