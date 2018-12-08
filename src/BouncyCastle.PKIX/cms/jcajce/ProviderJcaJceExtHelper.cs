namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;
	using JceSymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceSymmetricKeyUnwrapper;

	public class ProviderJcaJceExtHelper : ProviderJcaJceHelper, JcaJceExtHelper
	{
		public ProviderJcaJceExtHelper(Provider provider) : base(provider)
		{
		}

		public virtual JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
		{
			return (new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey)).setProvider(provider);
		}

		public virtual JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
		{
			return (new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo)).setProvider(provider);
		}

		public virtual SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
		{
			return (new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey)).setProvider(provider);
		}
	}
}