namespace org.bouncycastle.pkcs
{

	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// A class for creating EncryptedPrivateKeyInfo structures.
	/// <pre>
	/// EncryptedPrivateKeyInfo ::= SEQUENCE {
	///      encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
	///      encryptedData EncryptedData
	/// }
	/// 
	/// EncryptedData ::= OCTET STRING
	/// 
	/// KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
	///          ... -- For local profiles
	/// }
	/// </pre>
	/// </summary>
	public class PKCS8EncryptedPrivateKeyInfoBuilder
	{
		private PrivateKeyInfo privateKeyInfo;

		public PKCS8EncryptedPrivateKeyInfoBuilder(byte[] privateKeyInfo) : this(PrivateKeyInfo.getInstance(privateKeyInfo))
		{
		}

		public PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo privateKeyInfo)
		{
			this.privateKeyInfo = privateKeyInfo;
		}

		public virtual PKCS8EncryptedPrivateKeyInfo build(OutputEncryptor encryptor)
		{
			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				OutputStream cOut = encryptor.getOutputStream(bOut);

				cOut.write(privateKeyInfo.getEncoded());

				cOut.close();

				return new PKCS8EncryptedPrivateKeyInfo(new EncryptedPrivateKeyInfo(encryptor.getAlgorithmIdentifier(), bOut.toByteArray()));
			}
			catch (IOException)
			{
				throw new IllegalStateException("cannot encode privateKeyInfo");
			}
		}
	}

}