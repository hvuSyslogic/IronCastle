namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;
	using JceSymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceSymmetricKeyUnwrapper;

	public class NamedJcaJceExtHelper : NamedJcaJceHelper, JcaJceExtHelper
	{
		public NamedJcaJceExtHelper(string providerName) : base(providerName)
		{
		}

		public virtual JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
		{
			return (new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey)).setProvider(providerName);
		}

		public virtual JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
		{
			return (new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo)).setProvider(providerName);
		}

		public virtual SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
		{
			return (new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey)).setProvider(providerName);
		}
	}
}