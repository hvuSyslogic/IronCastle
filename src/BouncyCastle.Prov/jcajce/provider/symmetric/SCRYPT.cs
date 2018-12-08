using org.bouncycastle.asn1.misc;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PasswordConverter = org.bouncycastle.crypto.PasswordConverter;
	using SCrypt = org.bouncycastle.crypto.generators.SCrypt;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using ScryptKeySpec = org.bouncycastle.jcajce.spec.ScryptKeySpec;

	public class SCRYPT
	{
		private SCRYPT()
		{

		}

		public class BasePBKDF2 : BaseSecretKeyFactory
		{
			internal int scheme;

			public BasePBKDF2(string name, int scheme) : base(name, org.bouncycastle.asn1.misc.MiscObjectIdentifiers_Fields.id_scrypt)
			{

				this.scheme = scheme;
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is ScryptKeySpec)
				{
					ScryptKeySpec pbeSpec = (ScryptKeySpec)keySpec;

					if (pbeSpec.getSalt() == null)
					{
						throw new IllegalArgumentException("Salt S must be provided.");
					}
					if (pbeSpec.getCostParameter() <= 1)
					{
						throw new IllegalArgumentException("Cost parameter N must be > 1.");
					}

					if (pbeSpec.getKeyLength() <= 0)
					{
						throw new InvalidKeySpecException("positive key length required: " + pbeSpec.getKeyLength());
					}

					if (pbeSpec.getPassword().Length == 0)
					{
						throw new IllegalArgumentException("password empty");
					}

					CipherParameters param = new KeyParameter(SCrypt.generate(PasswordConverter.UTF8.convert(pbeSpec.getPassword()), pbeSpec.getSalt(), pbeSpec.getCostParameter(), pbeSpec.getBlockSize(), pbeSpec.getParallelizationParameter(), pbeSpec.getKeyLength() / 8));

					return new BCPBEKey(this.algName, pbeSpec, param);
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}
		}

		public class ScryptWithUTF8 : BasePBKDF2
		{
			public ScryptWithUTF8() : base("SCRYPT", PKCS5S2_UTF8)
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SCRYPT).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8");
				provider.addAlgorithm("SecretKeyFactory", MiscObjectIdentifiers_Fields.id_scrypt, PREFIX + "$ScryptWithUTF8");
			}
		}
	}

}