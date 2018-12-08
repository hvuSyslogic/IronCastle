namespace org.bouncycastle.jcajce.provider.util
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

	public abstract class AsymmetricAlgorithmProvider : AlgorithmProvider
	{
		public virtual void addSignatureAlgorithm(ConfigurableProvider provider, string algorithm, string className, ASN1ObjectIdentifier oid)
		{
			provider.addAlgorithm("Signature." + algorithm, className);
			provider.addAlgorithm("Alg.Alias.Signature." + oid, algorithm);
			provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, algorithm);
		}

		public virtual void addSignatureAlgorithm(ConfigurableProvider provider, string digest, string algorithm, string className, ASN1ObjectIdentifier oid)
		{
			string mainName = digest + "WITH" + algorithm;
			string jdk11Variation1 = digest + "with" + algorithm;
			string jdk11Variation2 = digest + "With" + algorithm;
			string alias = digest + "/" + algorithm;

			provider.addAlgorithm("Signature." + mainName, className);
			provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
			provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
			provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);
			provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
			provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
		}

		public virtual void registerOid(ConfigurableProvider provider, ASN1ObjectIdentifier oid, string name, AsymmetricKeyInfoConverter keyFactory)
		{
			provider.addAlgorithm("Alg.Alias.KeyFactory." + oid, name);
			provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + oid, name);

			provider.addKeyInfoConverter(oid, keyFactory);
		}

		public virtual void registerOidAlgorithmParameters(ConfigurableProvider provider, ASN1ObjectIdentifier oid, string name)
		{
			provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + oid, name);
		}

		public virtual void registerOidAlgorithmParameterGenerator(ConfigurableProvider provider, ASN1ObjectIdentifier oid, string name)
		{
			provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + oid, name);
			provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + oid, name);
		}
	}

}