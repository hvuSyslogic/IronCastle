using System;

namespace org.bouncycastle.@operator.jcajce
{

	using GenericHybridParameters = org.bouncycastle.asn1.cms.GenericHybridParameters;
	using RsaKemParameters = org.bouncycastle.asn1.cms.RsaKemParameters;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DEROtherInfo = org.bouncycastle.crypto.util.DEROtherInfo;
	using KTSParameterSpec = org.bouncycastle.jcajce.spec.KTSParameterSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JceKTSKeyUnwrapper : AsymmetricKeyUnwrapper
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private Map extraMappings = new HashMap();
		private PrivateKey privKey;
		private byte[] partyUInfo;
		private byte[] partyVInfo;

		public JceKTSKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, PrivateKey privKey, byte[] partyUInfo, byte[] partyVInfo) : base(algorithmIdentifier)
		{

			this.privKey = privKey;
			this.partyUInfo = Arrays.clone(partyUInfo);
			this.partyVInfo = Arrays.clone(partyVInfo);
		}

		public virtual JceKTSKeyUnwrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceKTSKeyUnwrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public override GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
		{
			GenericHybridParameters @params = GenericHybridParameters.getInstance(this.getAlgorithmIdentifier().getParameters());
			Cipher keyCipher = helper.createAsymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm(), extraMappings);
			string symmetricWrappingAlg = helper.getWrappingAlgorithmName(@params.getDem().getAlgorithm());
			RsaKemParameters kemParameters = RsaKemParameters.getInstance(@params.getKem().getParameters());
			int keySizeInBits = kemParameters.getKeyLength().intValue() * 8;
			Key sKey;

			try
			{
				DEROtherInfo otherInfo = (new DEROtherInfo.Builder(@params.getDem(), partyUInfo, partyVInfo)).build();
				KTSParameterSpec ktsSpec = (new KTSParameterSpec.Builder(symmetricWrappingAlg, keySizeInBits, otherInfo.getEncoded())).withKdfAlgorithm(kemParameters.getKeyDerivationFunction()).build();

				keyCipher.init(Cipher.UNWRAP_MODE, privKey, ktsSpec);

				sKey = keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
			}
			catch (Exception e)
			{
				throw new OperatorException("Unable to unwrap contents key: " + e.Message, e);
			}

			return new JceGenericKey(encryptedKeyAlgorithm, sKey);
		}
	}

}