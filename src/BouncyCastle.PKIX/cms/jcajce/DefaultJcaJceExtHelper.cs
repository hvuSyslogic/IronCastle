namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;
	using JceSymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceSymmetricKeyUnwrapper;

	public class DefaultJcaJceExtHelper : DefaultJcaJceHelper, JcaJceExtHelper
	{
		public virtual JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
		{
			return new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
		}

		public virtual JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
		{
			return new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo);
		}

		public virtual SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
		{
			return new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
		}
	}

}