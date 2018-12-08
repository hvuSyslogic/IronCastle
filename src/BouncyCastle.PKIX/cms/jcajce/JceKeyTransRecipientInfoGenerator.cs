namespace org.bouncycastle.cms.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using JceAsymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyWrapper;

	public class JceKeyTransRecipientInfoGenerator : KeyTransRecipientInfoGenerator
	{
		public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert) : base(new IssuerAndSerialNumber((new JcaX509CertificateHolder(recipientCert)).toASN1Structure()), new JceAsymmetricKeyWrapper(recipientCert))
		{
		}

		public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey) : base(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(publicKey))
		{
		}

		/// <summary>
		/// Create a generator overriding the algorithm type implied by the public key in the certificate passed in.
		/// </summary>
		/// <param name="recipientCert"> certificate carrying the public key. </param>
		/// <param name="algorithmIdentifier"> the identifier and parameters for the encryption algorithm to be used. </param>
		public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmIdentifier algorithmIdentifier) : base(new IssuerAndSerialNumber((new JcaX509CertificateHolder(recipientCert)).toASN1Structure()), new JceAsymmetricKeyWrapper(algorithmIdentifier, recipientCert.getPublicKey()))
		{
		}

		/// <summary>
		/// Create a generator overriding the algorithm type implied by the public key passed in.
		/// </summary>
		/// <param name="subjectKeyIdentifier">  the subject key identifier value to associate with the public key. </param>
		/// <param name="algorithmIdentifier">  the identifier and parameters for the encryption algorithm to be used. </param>
		/// <param name="publicKey"> the public key to use. </param>
		public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier algorithmIdentifier, PublicKey publicKey) : base(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(algorithmIdentifier, publicKey))
		{
		}

		public virtual JceKeyTransRecipientInfoGenerator setProvider(string providerName)
		{
			((JceAsymmetricKeyWrapper)this.wrapper).setProvider(providerName);

			return this;
		}

		public virtual JceKeyTransRecipientInfoGenerator setProvider(Provider provider)
		{
			((JceAsymmetricKeyWrapper)this.wrapper).setProvider(provider);

			return this;
		}

		/// <summary>
		/// Internally algorithm ids are converted into cipher names using a lookup table. For some providers
		/// the standard lookup table won't work. Use this method to establish a specific mapping from an
		/// algorithm identifier to a specific algorithm.
		/// <para>
		///     For example:
		/// <pre>
		///     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="algorithm">  OID of algorithm in recipient. </param>
		/// <param name="algorithmName"> JCE algorithm name to use. </param>
		/// <returns> the current RecipientInfoGenerator. </returns>
		public virtual JceKeyTransRecipientInfoGenerator setAlgorithmMapping(ASN1ObjectIdentifier algorithm, string algorithmName)
		{
			((JceAsymmetricKeyWrapper)this.wrapper).setAlgorithmMapping(algorithm, algorithmName);

			return this;
		}
	}
}