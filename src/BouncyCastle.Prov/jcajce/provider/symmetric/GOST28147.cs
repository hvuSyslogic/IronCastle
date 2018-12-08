using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GOST28147Parameters = org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using CryptoProWrapEngine = org.bouncycastle.crypto.engines.CryptoProWrapEngine;
	using GOST28147Engine = org.bouncycastle.crypto.engines.GOST28147Engine;
	using GOST28147WrapEngine = org.bouncycastle.crypto.engines.GOST28147WrapEngine;
	using GOST28147Mac = org.bouncycastle.crypto.macs.GOST28147Mac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using GCFBBlockCipher = org.bouncycastle.crypto.modes.GCFBBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using GOST28147ParameterSpec = org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;

	public sealed class GOST28147
	{
		private static Map<ASN1ObjectIdentifier, string> oidMappings = new HashMap<ASN1ObjectIdentifier, string>();
		private static Map<string, ASN1ObjectIdentifier> nameMappings = new HashMap<string, ASN1ObjectIdentifier>();

		static GOST28147()
		{
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_TestParamSet, "E-TEST");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
			oidMappings.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_28147_param_Z, "Param-Z");

			nameMappings.put("E-A", CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet);
			nameMappings.put("E-B", CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_B_ParamSet);
			nameMappings.put("E-C", CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_C_ParamSet);
			nameMappings.put("E-D", CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_D_ParamSet);
			nameMappings.put("Param-Z", RosstandartObjectIdentifiers_Fields.id_tc26_gost_28147_param_Z);
		}

		private GOST28147()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new GOST28147Engine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new GOST28147Engine()), 64)
			{
			}
		}

		public class GCFB : BaseBlockCipher
		{
			public GCFB() : base(new BufferedBlockCipher(new GCFBBlockCipher(new GOST28147Engine())), 64)
			{
			}
		}

		public class GostWrap : BaseWrapCipher
		{
			public GostWrap() : base(new GOST28147WrapEngine())
			{
			}
		}

		public class CryptoProWrap : BaseWrapCipher
		{
			public CryptoProWrap() : base(new CryptoProWrapEngine())
			{
			}
		}

		/// <summary>
		/// GOST28147
		/// </summary>
		public class Mac : BaseMac
		{
			public Mac() : base(new GOST28147Mac())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(256)
			{
			}

			public KeyGen(int keySize) : base("GOST28147", keySize, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			internal byte[] iv = new byte[8];
			internal byte[] sBox = GOST28147Engine.getSBox("E-A");

			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				if (genParamSpec is GOST28147ParameterSpec)
				{
					  this.sBox = ((GOST28147ParameterSpec)genParamSpec).getSBox();
				}
				else
				{
					throw new InvalidAlgorithmParameterException("parameter spec not supported");
				}
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("GOST28147");
					@params.init(new GOST28147ParameterSpec(sBox, iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public abstract class BaseAlgParams : BaseAlgorithmParameters
		{
			internal ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet;
			internal byte[] iv;

			public void engineInit(byte[] encoding)
			{
				engineInit(encoding, "ASN.1");
			}

			public byte[] engineGetEncoded()
			{
				return engineGetEncoded("ASN.1");
			}

			public byte[] engineGetEncoded(string format)
			{
				if (isASN1FormatString(format))
				{
					return localGetEncoded();
				}

				throw new IOException("Unknown parameter format: " + format);
			}

			public void engineInit(byte[] @params, string format)
			{
				if (@params == null)
				{
					throw new NullPointerException("Encoded parameters cannot be null");
				}

				if (isASN1FormatString(format))
				{
					try
					{
						localInit(@params);
					}
					catch (IOException e)
					{
						throw e;
					}
					catch (Exception e)
					{
						throw new IOException("Parameter parsing failed: " + e.Message);
					}
				}
				else
				{
					throw new IOException("Unknown parameter format: " + format);
				}
			}

			public virtual byte[] localGetEncoded()
			{
				return (new GOST28147Parameters(iv, sBox)).getEncoded();
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(iv);
				}

				if (paramSpec == typeof(GOST28147ParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
				{
					return new GOST28147ParameterSpec(sBox, iv);
				}

				throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (paramSpec is IvParameterSpec)
				{
					this.iv = ((IvParameterSpec)paramSpec).getIV();
				}
				else if (paramSpec is GOST28147ParameterSpec)
				{
					this.iv = ((GOST28147ParameterSpec)paramSpec).getIV();
					try
					{
						this.sBox = getSBoxOID((((GOST28147ParameterSpec)paramSpec).getSBox()));
					}
					catch (IllegalArgumentException e)
					{
						throw new InvalidParameterSpecException(e.getMessage());
					}
				}
				else
				{
					throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
				}
			}

			protected internal static ASN1ObjectIdentifier getSBoxOID(string name)
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)nameMappings.get(name);

				if (oid == null)
				{
					throw new IllegalArgumentException("Unknown SBOX name: " + name);
				}

				return oid;
			}

			protected internal static ASN1ObjectIdentifier getSBoxOID(byte[] sBox)
			{
				return getSBoxOID(GOST28147Engine.getSBoxName(sBox));
			}

			public abstract void localInit(byte[] @params);
		}

		public class AlgParams : BaseAlgParams
		{
			internal ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet;
			internal byte[] iv;

			public override byte[] localGetEncoded()
			{
				return (new GOST28147Parameters(iv, sBox)).getEncoded();
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(iv);
				}

				if (paramSpec == typeof(GOST28147ParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
				{
					return new GOST28147ParameterSpec(sBox, iv);
				}

				throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
			}

			public override void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (paramSpec is IvParameterSpec)
				{
					this.iv = ((IvParameterSpec)paramSpec).getIV();
				}
				else if (paramSpec is GOST28147ParameterSpec)
				{
					this.iv = ((GOST28147ParameterSpec)paramSpec).getIV();
					try
					{
						this.sBox = getSBoxOID((((GOST28147ParameterSpec)paramSpec).getSBox()));
					}
					catch (IllegalArgumentException e)
					{
						throw new InvalidParameterSpecException(e.getMessage());
					}
				}
				else
				{
					throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
				}
			}

			public override void localInit(byte[] @params)
			{
				ASN1Primitive asn1Params = ASN1Primitive.fromByteArray(@params);

				if (asn1Params is ASN1OctetString)
				{
					this.iv = ASN1OctetString.getInstance(asn1Params).getOctets();
				}
				else if (asn1Params is ASN1Sequence)
				{
					GOST28147Parameters gParams = GOST28147Parameters.getInstance(asn1Params);

					this.sBox = gParams.getEncryptionParamSet();
					this.iv = gParams.getIV();
				}
				else
				{
					throw new IOException("Unable to recognize parameters");
				}
			}

			public virtual string engineToString()
			{
				return "GOST 28147 IV Parameters";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(GOST28147).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.GOST28147", PREFIX + "$ECB");
				provider.addAlgorithm("Alg.Alias.Cipher.GOST", "GOST28147");
				provider.addAlgorithm("Alg.Alias.Cipher.GOST-28147", "GOST28147");
				provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, PREFIX + "$GCFB");

				provider.addAlgorithm("KeyGenerator.GOST28147", PREFIX + "$KeyGen");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST", "GOST28147");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST-28147", "GOST28147");
				provider.addAlgorithm("Alg.Alias.KeyGenerator." + CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, "GOST28147");

				provider.addAlgorithm("AlgorithmParameters." + "GOST28147", PREFIX + "$AlgParams");
				provider.addAlgorithm("AlgorithmParameterGenerator." + "GOST28147", PREFIX + "$AlgParamGen");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, "GOST28147");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, "GOST28147");

				provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap, PREFIX + "$CryptoProWrap");
				provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers_Fields.id_Gost28147_89_None_KeyWrap, PREFIX + "$GostWrap");

				provider.addAlgorithm("Mac.GOST28147MAC", PREFIX + "$Mac");
				provider.addAlgorithm("Alg.Alias.Mac.GOST28147", "GOST28147MAC");
			}
		}
	}

}