namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;

	public interface JcaJceExtHelper : JcaJceHelper
	{
		JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey);

		JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo);

		SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey);
	}

}