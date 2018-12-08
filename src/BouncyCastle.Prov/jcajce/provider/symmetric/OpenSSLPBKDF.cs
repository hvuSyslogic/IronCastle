namespace org.bouncycastle.jcajce.provider.symmetric
{


	using OpenSSLPBEParametersGenerator = org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using Strings = org.bouncycastle.util.Strings;

	public sealed class OpenSSLPBKDF
	{
		private OpenSSLPBKDF()
		{
		}

		public class PBKDF : BaseSecretKeyFactory
		{
			public PBKDF() : base("PBKDF-OpenSSL", null)
			{
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is PBEKeySpec)
				{
					PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

					if (pbeSpec.getSalt() == null)
					{
						throw new InvalidKeySpecException("missing required salt");
					}

					if (pbeSpec.getIterationCount() <= 0)
					{
						throw new InvalidKeySpecException("positive iteration count required: " + pbeSpec.getIterationCount());
					}

					if (pbeSpec.getKeyLength() <= 0)
					{
						throw new InvalidKeySpecException("positive key length required: " + pbeSpec.getKeyLength());
					}

					if (pbeSpec.getPassword().Length == 0)
					{
						throw new IllegalArgumentException("password empty");
					}

					OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

					pGen.init(Strings.toByteArray(pbeSpec.getPassword()), pbeSpec.getSalt());

					return new SecretKeySpec(((KeyParameter)pGen.generateDerivedParameters(pbeSpec.getKeyLength())).getKey(), "OpenSSLPBKDF");
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(OpenSSLPBKDF).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("SecretKeyFactory.PBKDF-OPENSSL", PREFIX + "$PBKDF");
			}
		}
	}

}