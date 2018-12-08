using org.bouncycastle.asn1.misc;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using CAST5CBCParameters = org.bouncycastle.asn1.misc.CAST5CBCParameters;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using CAST5Engine = org.bouncycastle.crypto.engines.CAST5Engine;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class CAST5
	{
		private CAST5()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new CAST5Engine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new CAST5Engine()), 64)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("CAST5", 128, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for CAST5 parameter generation.");
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
					@params = createParametersInstance("CAST5");
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
			internal int keyLength = 128;

			public virtual byte[] engineGetEncoded()
			{
				byte[] tmp = new byte[iv.Length];

				JavaSystem.arraycopy(iv, 0, tmp, 0, iv.Length);
				return tmp;
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (this.isASN1FormatString(format))
				{
					return (new CAST5CBCParameters(engineGetEncoded(), keyLength)).getEncoded();
				}

				if (format.Equals("RAW"))
				{
					return engineGetEncoded();
				}


				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(iv);
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to CAST5 parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (paramSpec is IvParameterSpec)
				{
					this.iv = ((IvParameterSpec)paramSpec).getIV();
				}
				else
				{
					throw new InvalidParameterSpecException("IvParameterSpec required to initialise a CAST5 parameters algorithm parameters object");
				}
			}

			public virtual void engineInit(byte[] @params)
			{
				this.iv = new byte[@params.Length];

				JavaSystem.arraycopy(@params, 0, iv, 0, iv.Length);
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (this.isASN1FormatString(format))
				{
					ASN1InputStream aIn = new ASN1InputStream(@params);
					CAST5CBCParameters p = CAST5CBCParameters.getInstance(aIn.readObject());

					keyLength = p.getKeyLength();

					iv = p.getIV();

					return;
				}

				if (format.Equals("RAW"))
				{
					engineInit(@params);
					return;
				}

				throw new IOException("Unknown parameters format in IV parameters object");
			}

			public virtual string engineToString()
			{
				return "CAST5 Parameters";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(CAST5).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("AlgorithmParameters.CAST5", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.1.2.840.113533.7.66.10", "CAST5");

				provider.addAlgorithm("AlgorithmParameterGenerator.CAST5", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.1.2.840.113533.7.66.10", "CAST5");

				provider.addAlgorithm("Cipher.CAST5", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", MiscObjectIdentifiers_Fields.cast5CBC, PREFIX + "$CBC");

				provider.addAlgorithm("KeyGenerator.CAST5", PREFIX + "$KeyGen");
				provider.addAlgorithm("Alg.Alias.KeyGenerator", MiscObjectIdentifiers_Fields.cast5CBC, "CAST5");

			}
		}
	}

}