using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using RC532Engine = org.bouncycastle.crypto.engines.RC532Engine;
	using RC564Engine = org.bouncycastle.crypto.engines.RC564Engine;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class RC5
	{
		private RC5()
		{
		}

		/// <summary>
		/// RC5
		/// </summary>
		public class ECB32 : BaseBlockCipher
		{
			public ECB32() : base(new RC532Engine())
			{
			}
		}

		/// <summary>
		/// RC564
		/// </summary>
		public class ECB64 : BaseBlockCipher
		{
			public ECB64() : base(new RC564Engine())
			{
			}
		}

		public class CBC32 : BaseBlockCipher
		{
			public CBC32() : base(new CBCBlockCipher(new RC532Engine()), 64)
			{
			}
		}

		public class KeyGen32 : BaseKeyGenerator
		{
			public KeyGen32() : base("RC5", 128, new CipherKeyGenerator())
			{
			}
		}

		/// <summary>
		/// RC5
		/// </summary>
		public class KeyGen64 : BaseKeyGenerator
		{
			public KeyGen64() : base("RC5-64", 256, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC5 parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[8];

				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("RC5");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class Mac32 : BaseMac
		{
			public Mac32() : base(new CBCBlockCipherMac(new RC532Engine()))
			{
			}
		}

		public class CFB8Mac32 : BaseMac
		{
			public CFB8Mac32() : base(new CFBBlockCipherMac(new RC532Engine()))
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "RC5 IV";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(RC5).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.RC5", PREFIX + "$ECB32");
				provider.addAlgorithm("Alg.Alias.Cipher.RC5-32", "RC5");
				provider.addAlgorithm("Cipher.RC5-64", PREFIX + "$ECB64");
				provider.addAlgorithm("KeyGenerator.RC5", PREFIX + "$KeyGen32");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.RC5-32", "RC5");
				provider.addAlgorithm("KeyGenerator.RC5-64", PREFIX + "$KeyGen64");
				provider.addAlgorithm("AlgorithmParameters.RC5", PREFIX + "$AlgParams");
				provider.addAlgorithm("AlgorithmParameters.RC5-64", PREFIX + "$AlgParams");
				provider.addAlgorithm("Mac.RC5MAC", PREFIX + "$Mac32");
				provider.addAlgorithm("Alg.Alias.Mac.RC5", "RC5MAC");
				provider.addAlgorithm("Mac.RC5MAC/CFB8", PREFIX + "$CFB8Mac32");
				provider.addAlgorithm("Alg.Alias.Mac.RC5/CFB8", "RC5MAC/CFB8");

			}
		}
	}

}