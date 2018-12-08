namespace org.bouncycastle.cert.crmf.jcajce
{

	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using KeyWrapper = org.bouncycastle.@operator.KeyWrapper;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// JCA convenience class for EncryptedValueBuilder
	/// </summary>
	public class JcaEncryptedValueBuilder : EncryptedValueBuilder
	{
		public JcaEncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor) : base(wrapper, encryptor)
		{
		}

		/// <summary>
		/// Build an EncryptedValue structure containing the passed in certificate.
		/// </summary>
		/// <param name="certificate"> the certificate to be encrypted. </param>
		/// <returns> an EncryptedValue containing the encrypted certificate. </returns>
		/// <exception cref="CRMFException"> on a failure to encrypt the data, or wrap the symmetric key for this value. </exception>
		public virtual EncryptedValue build(X509Certificate certificate)
		{
			return build(new JcaX509CertificateHolder(certificate));
		}

		/// <summary>
		/// Build an EncryptedValue structure containing the private key details contained in
		/// the passed PrivateKey.
		/// </summary>
		/// <param name="privateKey">  a PKCS#8 private key info structure. </param>
		/// <returns> an EncryptedValue containing an EncryptedPrivateKeyInfo structure. </returns>
		/// <exception cref="CRMFException"> on a failure to encrypt the data, or wrap the symmetric key for this value. </exception>
		public virtual EncryptedValue build(PrivateKey privateKey)
		{
			return build(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
		}
	}

}