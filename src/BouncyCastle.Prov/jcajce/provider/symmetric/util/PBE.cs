using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using GOST3411Digest = org.bouncycastle.crypto.digests.GOST3411Digest;
	using MD2Digest = org.bouncycastle.crypto.digests.MD2Digest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using TigerDigest = org.bouncycastle.crypto.digests.TigerDigest;
	using OpenSSLPBEParametersGenerator = org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using PKCS5S1ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using DESParameters = org.bouncycastle.crypto.@params.DESParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;

	public interface PBE
	{
		//
		// PBE Based encryption constants - by default we do PKCS12 with SHA-1
		//

		/// <summary>
		/// uses the appropriate mixer to generate the key and IV if necessary.
		/// </summary>
	}

	public static class PBE_Fields
	{
		public const int MD5 = 0;
		public const int SHA1 = 1;
		public const int RIPEMD160 = 2;
		public const int TIGER = 3;
		public const int SHA256 = 4;
		public const int MD2 = 5;
		public const int GOST3411 = 6;
		public const int SHA224 = 7;
		public const int SHA384 = 8;
		public const int SHA512 = 9;
		public const int SHA3_224 = 10;
		public const int SHA3_256 = 11;
		public const int SHA3_384 = 12;
		public const int SHA3_512 = 13;
		public const int PKCS5S1 = 0;
		public const int PKCS5S2 = 1;
		public const int PKCS12 = 2;
		public const int OPENSSL = 3;
		public const int PKCS5S1_UTF8 = 4;
		public const int PKCS5S2_UTF8 = 5;
	}

	public class PBE_Util
	{
		internal static PBEParametersGenerator makePBEGenerator(int type, int hash)
		{
			PBEParametersGenerator generator;

			if (type == PBE_Fields.PKCS5S1 || type == PBE_Fields.PKCS5S1_UTF8)
			{
				switch (hash)
				{
				case PBE_Fields.MD2:
					generator = new PKCS5S1ParametersGenerator(new MD2Digest());
					break;
				case PBE_Fields.MD5:
					generator = new PKCS5S1ParametersGenerator(DigestFactory.createMD5());
					break;
				case PBE_Fields.SHA1:
					generator = new PKCS5S1ParametersGenerator(DigestFactory.createSHA1());
					break;
				default:
					throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
				}
			}
			else if (type == PBE_Fields.PKCS5S2 || type == PBE_Fields.PKCS5S2_UTF8)
			{
				switch (hash)
				{
				case PBE_Fields.MD2:
					generator = new PKCS5S2ParametersGenerator(new MD2Digest());
					break;
				case PBE_Fields.MD5:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createMD5());
					break;
				case PBE_Fields.SHA1:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA1());
					break;
				case PBE_Fields.RIPEMD160:
					generator = new PKCS5S2ParametersGenerator(new RIPEMD160Digest());
					break;
				case PBE_Fields.TIGER:
					generator = new PKCS5S2ParametersGenerator(new TigerDigest());
					break;
				case PBE_Fields.SHA256:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
					break;
				case PBE_Fields.GOST3411:
					generator = new PKCS5S2ParametersGenerator(new GOST3411Digest());
					break;
				case PBE_Fields.SHA224:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA224());
					break;
				case PBE_Fields.SHA384:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA384());
					break;
				case PBE_Fields.SHA512:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
					break;
				case PBE_Fields.SHA3_224:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_224());
					break;
				case PBE_Fields.SHA3_256:
					 generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_256());
					 break;
				case PBE_Fields.SHA3_384:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_384());
					break;
				case PBE_Fields.SHA3_512:
					generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_512());
					break;
				default:
					throw new IllegalStateException("unknown digest scheme for PBE PKCS5S2 encryption.");
				}
			}
			else if (type == PBE_Fields.PKCS12)
			{
				switch (hash)
				{
				case PBE_Fields.MD2:
					generator = new PKCS12ParametersGenerator(new MD2Digest());
					break;
				case PBE_Fields.MD5:
					generator = new PKCS12ParametersGenerator(DigestFactory.createMD5());
					break;
				case PBE_Fields.SHA1:
					generator = new PKCS12ParametersGenerator(DigestFactory.createSHA1());
					break;
				case PBE_Fields.RIPEMD160:
					generator = new PKCS12ParametersGenerator(new RIPEMD160Digest());
					break;
				case PBE_Fields.TIGER:
					generator = new PKCS12ParametersGenerator(new TigerDigest());
					break;
				case PBE_Fields.SHA256:
					generator = new PKCS12ParametersGenerator(DigestFactory.createSHA256());
					break;
				case PBE_Fields.GOST3411:
					generator = new PKCS12ParametersGenerator(new GOST3411Digest());
					break;
				case PBE_Fields.SHA224:
					generator = new PKCS12ParametersGenerator(DigestFactory.createSHA224());
					break;
				case PBE_Fields.SHA384:
					generator = new PKCS12ParametersGenerator(DigestFactory.createSHA384());
					break;
				case PBE_Fields.SHA512:
					generator = new PKCS12ParametersGenerator(DigestFactory.createSHA512());
					break;
				default:
					throw new IllegalStateException("unknown digest scheme for PBE encryption.");
				}
			}
			else
			{
				generator = new OpenSSLPBEParametersGenerator();
			}

			return generator;
		}

		/// <summary>
		/// construct a key and iv (if necessary) suitable for use with a
		/// Cipher.
		/// </summary>
		public static CipherParameters makePBEParameters(byte[] pbeKey, int scheme, int digest, int keySize, int ivSize, AlgorithmParameterSpec spec, string targetAlgorithm)
		{
			if ((spec == null) || !(spec is PBEParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("Need a PBEParameter spec with a PBE key.");
			}

			PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
			PBEParametersGenerator generator = makePBEGenerator(scheme, digest);
			byte[] key = pbeKey;
			CipherParameters param;

	//            if (pbeKey.shouldTryWrongPKCS12())
	//            {
	//                key = new byte[2];
	//            }

			generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

			if (ivSize != 0)
			{
				param = generator.generateDerivedParameters(keySize, ivSize);
			}
			else
			{
				param = generator.generateDerivedParameters(keySize);
			}

			if (targetAlgorithm.StartsWith("DES", StringComparison.Ordinal))
			{
				if (param is ParametersWithIV)
				{
					KeyParameter kParam = (KeyParameter)((ParametersWithIV)param).getParameters();

					DESParameters.setOddParity(kParam.getKey());
				}
				else
				{
					KeyParameter kParam = (KeyParameter)param;

					DESParameters.setOddParity(kParam.getKey());
				}
			}

			return param;
		}

		/// <summary>
		/// construct a key and iv (if necessary) suitable for use with a 
		/// Cipher.
		/// </summary>
		public static CipherParameters makePBEParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec, string targetAlgorithm)
		{
			if ((spec == null) || !(spec is PBEParameterSpec))
			{
				throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
			}

			PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
			PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
			byte[] key = pbeKey.getEncoded();
			CipherParameters param;

			if (pbeKey.shouldTryWrongPKCS12())
			{
				key = new byte[2];
			}

			generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

			if (pbeKey.getIvSize() != 0)
			{
				param = generator.generateDerivedParameters(pbeKey.getKeySize(), pbeKey.getIvSize());
			}
			else
			{
				param = generator.generateDerivedParameters(pbeKey.getKeySize());
			}

			if (targetAlgorithm.StartsWith("DES", StringComparison.Ordinal))
			{
				if (param is ParametersWithIV)
				{
					KeyParameter kParam = (KeyParameter)((ParametersWithIV)param).getParameters();

					DESParameters.setOddParity(kParam.getKey());
				}
				else
				{
					KeyParameter kParam = (KeyParameter)param;

					DESParameters.setOddParity(kParam.getKey());
				}
			}

			return param;
		}

		/// <summary>
		/// generate a PBE based key suitable for a MAC algorithm, the
		/// key size is chosen according the MAC size, or the hashing algorithm,
		/// whichever is greater.
		/// </summary>
		public static CipherParameters makePBEMacParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec)
		{
			if ((spec == null) || !(spec is PBEParameterSpec))
			{
				throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
			}

			PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
			PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
			byte[] key = pbeKey.getEncoded();
			CipherParameters param;

			generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

			param = generator.generateDerivedMacParameters(pbeKey.getKeySize());

			return param;
		}

		/// <summary>
		/// generate a PBE based key suitable for a MAC algorithm, the
		/// key size is chosen according the MAC size, or the hashing algorithm,
		/// whichever is greater.
		/// </summary>
		public static CipherParameters makePBEMacParameters(PBEKeySpec keySpec, int type, int hash, int keySize)
		{
			PBEParametersGenerator generator = makePBEGenerator(type, hash);
			byte[] key;
			CipherParameters param;

			key = convertPassword(type, keySpec);

			generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());

			param = generator.generateDerivedMacParameters(keySize);

			for (int i = 0; i != key.Length; i++)
			{
				key[i] = 0;
			}

			return param;
		}

		/// <summary>
		/// construct a key and iv (if necessary) suitable for use with a 
		/// Cipher.
		/// </summary>
		public static CipherParameters makePBEParameters(PBEKeySpec keySpec, int type, int hash, int keySize, int ivSize)
		{
			PBEParametersGenerator generator = makePBEGenerator(type, hash);
			byte[] key;
			CipherParameters param;

			key = convertPassword(type, keySpec);

			generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());

			if (ivSize != 0)
			{
				param = generator.generateDerivedParameters(keySize, ivSize);
			}
			else
			{
				param = generator.generateDerivedParameters(keySize);
			}

			for (int i = 0; i != key.Length; i++)
			{
				key[i] = 0;
			}

			return param;
		}

		/// <summary>
		/// generate a PBE based key suitable for a MAC algorithm, the
		/// key size is chosen according the MAC size, or the hashing algorithm,
		/// whichever is greater.
		/// </summary>
		public static CipherParameters makePBEMacParameters(SecretKey key, int type, int hash, int keySize, PBEParameterSpec pbeSpec)
		{
			PBEParametersGenerator generator = makePBEGenerator(type, hash);
			CipherParameters param;

			byte[] keyBytes = key.getEncoded();

			generator.init(key.getEncoded(), pbeSpec.getSalt(), pbeSpec.getIterationCount());

			param = generator.generateDerivedMacParameters(keySize);

			for (int i = 0; i != keyBytes.Length; i++)
			{
				keyBytes[i] = 0;
			}

			return param;
		}

		internal static byte[] convertPassword(int type, PBEKeySpec keySpec)
		{
			byte[] key;

			if (type == PBE_Fields.PKCS12)
			{
				key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
			}
			else if (type == PBE_Fields.PKCS5S2_UTF8 || type == PBE_Fields.PKCS5S1_UTF8)
			{
				key = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(keySpec.getPassword());
			}
			else
			{
				key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
			}
			return key;
		}
	}

}