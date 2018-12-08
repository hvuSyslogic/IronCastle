using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Shacal2Engine = org.bouncycastle.crypto.engines.Shacal2Engine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public sealed class Shacal2
	{
		private Shacal2()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new BlockCipherProviderAnonymousInnerClass())
			{
			}

			public class BlockCipherProviderAnonymousInnerClass : BlockCipherProvider
			{
				public BlockCipher get()
				{
					return new Shacal2Engine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new Shacal2Engine()), 256) //block size
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new Shacal2Engine()))
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("SHACAL-2", 128, new CipherKeyGenerator()) //key size
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for Shacal2 parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[32]; // block size 256

				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("Shacal2");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}
				return @params;
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Shacal2 IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Shacal2).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Mac.Shacal-2CMAC", PREFIX + "$CMAC");

				provider.addAlgorithm("Cipher.Shacal2", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher.SHACAL-2", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.Shacal2", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameterGenerator.Shacal2", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("AlgorithmParameters.Shacal2", PREFIX + "$AlgParams");
				provider.addAlgorithm("KeyGenerator.SHACAL-2", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameterGenerator.SHACAL-2", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("AlgorithmParameters.SHACAL-2", PREFIX + "$AlgParams");
			}
		}
	}

}