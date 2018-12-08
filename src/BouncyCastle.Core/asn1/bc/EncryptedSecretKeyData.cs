namespace org.bouncycastle.asn1.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	///     EncryptedSecretKeyData ::= SEQUENCE {
	///         keyEncryptionAlgorithm AlgorithmIdentifier,
	///         encryptedKeyData OCTET STRING
	///     }
	/// </pre>
	/// </summary>
	public class EncryptedSecretKeyData : ASN1Object
	{
		private readonly AlgorithmIdentifier keyEncryptionAlgorithm;
		private readonly ASN1OctetString encryptedKeyData;

		public EncryptedSecretKeyData(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKeyData)
		{
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKeyData = new DEROctetString(Arrays.clone(encryptedKeyData));
		}

		private EncryptedSecretKeyData(ASN1Sequence seq)
		{
			this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.encryptedKeyData = ASN1OctetString.getInstance(seq.getObjectAt(1));
		}

		public static EncryptedSecretKeyData getInstance(object o)
		{
			if (o is EncryptedSecretKeyData)
			{
				return (EncryptedSecretKeyData)o;
			}
			else if (o != null)
			{
				return new EncryptedSecretKeyData(ASN1Sequence.getInstance(o));
			}

			return null;
		}


		public virtual AlgorithmIdentifier getKeyEncryptionAlgorithm()
		{
			return keyEncryptionAlgorithm;
		}

		public virtual byte[] getEncryptedKeyData()
		{
			return Arrays.clone(encryptedKeyData.getOctets());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyEncryptionAlgorithm);
			v.add(encryptedKeyData);

			return new DERSequence(v);
		}
	}

}