namespace org.bouncycastle.cert.jcajce
{

	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;

	public class JcaX509ContentVerifierProviderBuilder : X509ContentVerifierProviderBuilder
	{
		private JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder();

		public virtual JcaX509ContentVerifierProviderBuilder setProvider(Provider provider)
		{
			this.builder.setProvider(provider);

			return this;
		}

		public virtual JcaX509ContentVerifierProviderBuilder setProvider(string providerName)
		{
			this.builder.setProvider(providerName);

			return this;
		}

		public virtual ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
		{
			return builder.build(validatingKeyInfo);
		}

		public virtual ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
		{
			try
			{
				return builder.build(validatingKeyInfo);
			}
			catch (CertificateException e)
			{
				throw new OperatorCreationException("Unable to process certificate: " + e.Message, e);
			}
		}
	}

}