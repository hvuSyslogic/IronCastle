using org.bouncycastle.jcajce.provider.symmetric.util;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1;

namespace org.bouncycastle.jcajce.provider.symmetric
{


	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PasswordConverter = org.bouncycastle.crypto.PasswordConverter;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using PBE = org.bouncycastle.jcajce.provider.symmetric.util.PBE;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using PBKDF2KeySpec = org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
	using Integers = org.bouncycastle.util.Integers;

	public class PBEPBKDF2
	{
		private static readonly Map prfCodes = new HashMap();

		static PBEPBKDF2()
		{
			prfCodes.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, Integers.valueOf(PBE_Fields.GOST3411));
			prfCodes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, Integers.valueOf(PBE_Fields.SHA1));
			prfCodes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, Integers.valueOf(PBE_Fields.SHA256));
			prfCodes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, Integers.valueOf(PBE_Fields.SHA224));
			prfCodes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, Integers.valueOf(PBE_Fields.SHA384));
			prfCodes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, Integers.valueOf(PBE_Fields.SHA512));
			prfCodes.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, Integers.valueOf(PBE_Fields.SHA3_256));
			prfCodes.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, Integers.valueOf(PBE_Fields.SHA3_224));
			prfCodes.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, Integers.valueOf(PBE_Fields.SHA3_384));
			prfCodes.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, Integers.valueOf(PBE_Fields.SHA3_512));
		}

		private PBEPBKDF2()
		{

		}

		public class AlgParams : BaseAlgorithmParameters
		{
			internal PBKDF2Params @params;

			public virtual byte[] engineGetEncoded()
			{
				try
				{
					return @params.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException e)
				{
					throw new RuntimeException("Oooops! " + e.ToString());
				}
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (this.isASN1FormatString(format))
				{
					return engineGetEncoded();
				}

				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(PBEParameterSpec))
				{
					return new PBEParameterSpec(@params.getSalt(), @params.getIterationCount().intValue());
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to PBKDF2 PBE parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is PBEParameterSpec))
				{
					throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF2 PBE parameters algorithm parameters object");
				}

				PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

				this.@params = new PBKDF2Params(pbeSpec.getSalt(), pbeSpec.getIterationCount());
			}

			public virtual void engineInit(byte[] @params)
			{
				this.@params = PBKDF2Params.getInstance(ASN1Primitive.fromByteArray(@params));
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (this.isASN1FormatString(format))
				{
					engineInit(@params);
					return;
				}

				throw new IOException("Unknown parameters format in PBKDF2 parameters object");
			}

			public virtual string engineToString()
			{
				return "PBKDF2 Parameters";
			}
		}

		public class BasePBKDF2 : BaseSecretKeyFactory
		{
			internal int scheme;
			internal int defaultDigest;

			public BasePBKDF2(string name, int scheme) : this(name, scheme, SHA1)
			{
			}

			public BasePBKDF2(string name, int scheme, int defaultDigest) : base(name, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.id_PBKDF2)
			{

				this.scheme = scheme;
				this.defaultDigest = defaultDigest;
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is PBEKeySpec)
				{
					PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

					if (pbeSpec.getSalt() == null)
					{
						return new PBKDF2Key(((PBEKeySpec)keySpec).getPassword(), scheme == PKCS5S2 ? PasswordConverter.ASCII : PasswordConverter.UTF8);
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

					if (pbeSpec is PBKDF2KeySpec)
					{
						PBKDF2KeySpec spec = (PBKDF2KeySpec)pbeSpec;

						int digest = getDigestCode(spec.getPrf().getAlgorithm());
						int keySize = pbeSpec.getKeyLength();
						int ivSize = -1; // JDK 1,2 and earlier does not understand simplified version.
						CipherParameters param = PBE_Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);

						return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
					}
					else
					{
						int digest = defaultDigest;
						int keySize = pbeSpec.getKeyLength();
						int ivSize = -1; // JDK 1,2 and earlier does not understand simplified version.
						CipherParameters param = PBE_Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);

						return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
					}
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}


			public virtual int getDigestCode(ASN1ObjectIdentifier algorithm)
			{
				int? code = (int?)prfCodes.get(algorithm);
				if (code != null)
				{
					return code.Value;
				}

				throw new InvalidKeySpecException("Invalid KeySpec: unknown PRF algorithm " + algorithm);
			}
		}

		public class PBKDF2withUTF8 : BasePBKDF2
		{
			public PBKDF2withUTF8() : base("PBKDF2", PKCS5S2_UTF8)
			{
			}
		}

		public class PBKDF2withSHA224 : BasePBKDF2
		{
			public PBKDF2withSHA224() : base("PBKDF2", PKCS5S2_UTF8, SHA224)
			{
			}
		}

		public class PBKDF2withSHA256 : BasePBKDF2
		{
			public PBKDF2withSHA256() : base("PBKDF2", PKCS5S2_UTF8, SHA256)
			{
			}
		}

		public class PBKDF2withSHA384 : BasePBKDF2
		{
			public PBKDF2withSHA384() : base("PBKDF2", PKCS5S2_UTF8, SHA384)
			{
			}
		}

		public class PBKDF2withSHA512 : BasePBKDF2
		{
			public PBKDF2withSHA512() : base("PBKDF2", PKCS5S2_UTF8, SHA512)
			{
			}
		}

		public class PBKDF2withGOST3411 : BasePBKDF2
		{
			public PBKDF2withGOST3411() : base("PBKDF2", PKCS5S2_UTF8, GOST3411)
			{
			}
		}

		public class PBKDF2withSHA3_224 : BasePBKDF2
		{
			public PBKDF2withSHA3_224() : base("PBKDF2", PKCS5S2_UTF8, SHA3_224)
			{
			}
		}

		public class PBKDF2withSHA3_256 : BasePBKDF2
		{
			public PBKDF2withSHA3_256() : base("PBKDF2", PKCS5S2_UTF8, SHA3_256)
			{
			}
		}

		public class PBKDF2withSHA3_384 : BasePBKDF2
		{
			public PBKDF2withSHA3_384() : base("PBKDF2", PKCS5S2_UTF8, SHA3_384)
			{
			}
		}

		public class PBKDF2withSHA3_512 : BasePBKDF2
		{
			public PBKDF2withSHA3_512() : base("PBKDF2", PKCS5S2_UTF8, SHA3_512)
			{
			}
		}

		public class PBKDF2with8BIT : BasePBKDF2
		{
			public PBKDF2with8BIT() : base("PBKDF2", PKCS5S2)
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(PBEPBKDF2).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.PBKDF2", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.id_PBKDF2, "PBKDF2");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2", PREFIX + "$PBKDF2withUTF8");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1", "PBKDF2");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1ANDUTF8", "PBKDF2");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers_Fields.id_PBKDF2, "PBKDF2");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHASCII", PREFIX + "$PBKDF2with8BIT");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITH8BIT", "PBKDF2WITHASCII");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1AND8BIT", "PBKDF2WITHASCII");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA224", PREFIX + "$PBKDF2withSHA224");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA256", PREFIX + "$PBKDF2withSHA256");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA384", PREFIX + "$PBKDF2withSHA384");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA512", PREFIX + "$PBKDF2withSHA512");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-224", PREFIX + "$PBKDF2withSHA3_224");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-256", PREFIX + "$PBKDF2withSHA3_256");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-384", PREFIX + "$PBKDF2withSHA3_384");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-512", PREFIX + "$PBKDF2withSHA3_512");
				provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACGOST3411", PREFIX + "$PBKDF2withGOST3411");
			}
		}
	}

}