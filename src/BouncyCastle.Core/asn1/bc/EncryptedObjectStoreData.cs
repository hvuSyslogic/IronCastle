using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.bc
{
	
	/// <summary>
	/// <pre>
	/// EncryptedObjectStoreData ::= SEQUENCE {
	///     encryptionAlgorithm AlgorithmIdentifier
	///     encryptedContent OCTET STRING
	/// }
	/// </pre>
	/// </summary>
	public class EncryptedObjectStoreData : ASN1Object
	{
		private readonly AlgorithmIdentifier encryptionAlgorithm;
		private readonly ASN1OctetString encryptedContent;

		public EncryptedObjectStoreData(AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedContent)
		{
			this.encryptionAlgorithm = encryptionAlgorithm;
			this.encryptedContent = new DEROctetString(encryptedContent);
		}

		private EncryptedObjectStoreData(ASN1Sequence seq)
		{
			this.encryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.encryptedContent = ASN1OctetString.getInstance(seq.getObjectAt(1));
		}

		public static EncryptedObjectStoreData getInstance(object o)
		{
			if (o is EncryptedObjectStoreData)
			{
				return (EncryptedObjectStoreData)o;
			}
			else if (o != null)
			{
				return new EncryptedObjectStoreData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual ASN1OctetString getEncryptedContent()
		{
			return encryptedContent;
		}

		public virtual AlgorithmIdentifier getEncryptionAlgorithm()
		{
			return encryptionAlgorithm;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(encryptionAlgorithm);
			v.add(encryptedContent);

			return new DERSequence(v);
		}
	}
}