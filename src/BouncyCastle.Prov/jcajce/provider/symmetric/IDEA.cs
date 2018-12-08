using org.bouncycastle.asn1.misc;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using IDEACBCPar = org.bouncycastle.asn1.misc.IDEACBCPar;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using IDEAEngine = org.bouncycastle.crypto.engines.IDEAEngine;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class IDEA
	{
		private IDEA()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new IDEAEngine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new IDEAEngine()), 64)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("IDEA", 128, new CipherKeyGenerator())
			{
			}
		}

		public class PBEWithSHAAndIDEAKeyGen : PBESecretKeyFactory
		{
		   public PBEWithSHAAndIDEAKeyGen() : base("PBEwithSHAandIDEA-CBC", null, true, PKCS12, SHA1, 128, 64)
		   {
		   }
		}

		public class PBEWithSHAAndIDEA : BaseBlockCipher
		{
			public PBEWithSHAAndIDEA() : base(new CBCBlockCipher(new IDEAEngine()))
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for IDEA parameter generation.");
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
					@params = createParametersInstance("IDEA");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class AlgParams : BaseAlgorithmParameters
		{
			internal byte[] iv;

			public virtual byte[] engineGetEncoded()
			{
				return engineGetEncoded("ASN.1");
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (this.isASN1FormatString(format))
				{
					return (new IDEACBCPar(engineGetEncoded("RAW"))).getEncoded();
				}

				if (format.Equals("RAW"))
				{
					byte[] tmp = new byte[iv.Length];

					JavaSystem.arraycopy(iv, 0, tmp, 0, iv.Length);
					return tmp;
				}

				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(iv);
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is IvParameterSpec))
				{
					throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
				}

				this.iv = ((IvParameterSpec)paramSpec).getIV();
			}

			public virtual void engineInit(byte[] @params)
			{
				this.iv = new byte[@params.Length];

				JavaSystem.arraycopy(@params, 0, iv, 0, iv.Length);
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (format.Equals("RAW"))
				{
					engineInit(@params);
					return;
				}
				if (format.Equals("ASN.1"))
				{
					IDEACBCPar oct = IDEACBCPar.getInstance(@params);

					engineInit(oct.getIV());
					return;
				}

				throw new IOException("Unknown parameters format in IV parameters object");
			}

			public virtual string engineToString()
			{
				return "IDEA Parameters";
			}
		}

		public class Mac : BaseMac
		{
			public Mac() : base(new CBCBlockCipherMac(new IDEAEngine()))
			{
			}
		}

		public class CFB8Mac : BaseMac
		{
			public CFB8Mac() : base(new CFBBlockCipherMac(new IDEAEngine()))
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(IDEA).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameterGenerator.IDEA", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("AlgorithmParameterGenerator.1.3.6.1.4.1.188.7.1.1.2", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("AlgorithmParameters.IDEA", PREFIX + "$AlgParams");
				provider.addAlgorithm("AlgorithmParameters.1.3.6.1.4.1.188.7.1.1.2", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA-CBC", "PKCS12PBE");
				provider.addAlgorithm("Cipher.IDEA", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", MiscObjectIdentifiers_Fields.as_sys_sec_alg_ideaCBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher.PBEWITHSHAANDIDEA-CBC", PREFIX + "$PBEWithSHAAndIDEA");
				provider.addAlgorithm("KeyGenerator.IDEA", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", MiscObjectIdentifiers_Fields.as_sys_sec_alg_ideaCBC, PREFIX + "$KeyGen");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAANDIDEA-CBC", PREFIX + "$PBEWithSHAAndIDEAKeyGen");
				provider.addAlgorithm("Mac.IDEAMAC", PREFIX + "$Mac");
				provider.addAlgorithm("Alg.Alias.Mac.IDEA", "IDEAMAC");
				provider.addAlgorithm("Mac.IDEAMAC/CFB8", PREFIX + "$CFB8Mac");
				provider.addAlgorithm("Alg.Alias.Mac.IDEA/CFB8", "IDEAMAC/CFB8");
			}
		}
	}

}