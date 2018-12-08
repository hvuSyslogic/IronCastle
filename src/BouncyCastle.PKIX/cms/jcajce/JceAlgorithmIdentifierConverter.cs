namespace org.bouncycastle.cms.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class JceAlgorithmIdentifierConverter
	{
		private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		private SecureRandom random;

		public JceAlgorithmIdentifierConverter()
		{
		}

		public virtual JceAlgorithmIdentifierConverter setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		public virtual JceAlgorithmIdentifierConverter setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		public virtual AlgorithmParameters getAlgorithmParameters(AlgorithmIdentifier algorithmIdentifier)
		{
			ASN1Encodable parameters = algorithmIdentifier.getParameters();

			if (parameters == null)
			{
				return null;
			}

			try
			{
				AlgorithmParameters @params = helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());

				CMSUtils.loadParameters(@params, algorithmIdentifier.getParameters());

				return @params;
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new CMSException("can't find parameters for algorithm", e);
			}
			catch (NoSuchProviderException e)
			{
				throw new CMSException("can't find provider for algorithm", e);
			}
		}
	}

}