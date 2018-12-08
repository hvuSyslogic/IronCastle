using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509.qualified
{


	/// <summary>
	/// The BiometricData object.
	/// <pre>
	/// BiometricData  ::=  SEQUENCE {
	///       typeOfBiometricData  TypeOfBiometricData,
	///       hashAlgorithm        AlgorithmIdentifier,
	///       biometricDataHash    OCTET STRING,
	///       sourceDataUri        IA5String OPTIONAL  }
	/// </pre>
	/// </summary>
	public class BiometricData : ASN1Object
	{
		private TypeOfBiometricData typeOfBiometricData;
		private AlgorithmIdentifier hashAlgorithm;
		private ASN1OctetString biometricDataHash;
		private DERIA5String sourceDataUri;

		public static BiometricData getInstance(object obj)
		{
			if (obj is BiometricData)
			{
				return (BiometricData)obj;
			}

			if (obj != null)
			{
				return new BiometricData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private BiometricData(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			// typeOfBiometricData
			typeOfBiometricData = TypeOfBiometricData.getInstance(e.nextElement());
			// hashAlgorithm
			hashAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
			// biometricDataHash
			biometricDataHash = ASN1OctetString.getInstance(e.nextElement());
			// sourceDataUri
			if (e.hasMoreElements())
			{
				sourceDataUri = DERIA5String.getInstance(e.nextElement());
			}
		}

		public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm, ASN1OctetString biometricDataHash, DERIA5String sourceDataUri)
		{
			this.typeOfBiometricData = typeOfBiometricData;
			this.hashAlgorithm = hashAlgorithm;
			this.biometricDataHash = biometricDataHash;
			this.sourceDataUri = sourceDataUri;
		}

		public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm, ASN1OctetString biometricDataHash)
		{
			this.typeOfBiometricData = typeOfBiometricData;
			this.hashAlgorithm = hashAlgorithm;
			this.biometricDataHash = biometricDataHash;
			this.sourceDataUri = null;
		}

		public virtual TypeOfBiometricData getTypeOfBiometricData()
		{
			return typeOfBiometricData;
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual ASN1OctetString getBiometricDataHash()
		{
			return biometricDataHash;
		}

		public virtual DERIA5String getSourceDataUri()
		{
			return sourceDataUri;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();
			seq.add(typeOfBiometricData);
			seq.add(hashAlgorithm);
			seq.add(biometricDataHash);

			if (sourceDataUri != null)
			{
				seq.add(sourceDataUri);
			}

			return new DERSequence(seq);
		}
	}

}