namespace org.bouncycastle.cert.crmf.jcajce
{


	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePKMACValuesCalculator : PKMACValuesCalculator
	{
		private MessageDigest digest;
		private Mac mac;
		private CRMFHelper helper;

		public JcePKMACValuesCalculator()
		{
			this.helper = new CRMFHelper(new DefaultJcaJceHelper());
		}

		public virtual JcePKMACValuesCalculator setProvider(Provider provider)
		{
			this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcePKMACValuesCalculator setProvider(string providerName)
		{
			this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual void setup(AlgorithmIdentifier digAlg, AlgorithmIdentifier macAlg)
		{
			digest = helper.createDigest(digAlg.getAlgorithm());
			mac = helper.createMac(macAlg.getAlgorithm());
		}

		public virtual byte[] calculateDigest(byte[] data)
		{
			return digest.digest(data);
		}

		public virtual byte[] calculateMac(byte[] pwd, byte[] data)
		{
			try
			{
				mac.init(new SecretKeySpec(pwd, mac.getAlgorithm()));

				return mac.doFinal(data);
			}
			catch (GeneralSecurityException e)
			{
				throw new CRMFException("failure in setup: " + e.Message, e);
			}
		}
	}

}