namespace org.bouncycastle.jcajce.provider.digest
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public abstract class DigestAlgorithmProvider : AlgorithmProvider
	{
		public virtual void addHMACAlgorithm(ConfigurableProvider provider, string algorithm, string algorithmClassName, string keyGeneratorClassName)
		{
			string mainName = "HMAC" + algorithm;

			provider.addAlgorithm("Mac." + mainName, algorithmClassName);
			provider.addAlgorithm("Alg.Alias.Mac.HMAC-" + algorithm, mainName);
			provider.addAlgorithm("Alg.Alias.Mac.HMAC/" + algorithm, mainName);
			provider.addAlgorithm("KeyGenerator." + mainName, keyGeneratorClassName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator.HMAC-" + algorithm, mainName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator.HMAC/" + algorithm, mainName);
		}

		public virtual void addHMACAlias(ConfigurableProvider provider, string algorithm, ASN1ObjectIdentifier oid)
		{
			string mainName = "HMAC" + algorithm;

			provider.addAlgorithm("Alg.Alias.Mac." + oid, mainName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator." + oid, mainName);
		}
	}

}