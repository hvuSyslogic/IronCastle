using System;

namespace org.bouncycastle.jce.provider
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using PKCS5S1ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;

	/// <summary>
	/// Generator for PBE derived keys and ivs as defined by PKCS 12 V1.0,
	/// with a bug affecting 180 bit plus keys - this class is only here to
	/// allow smooth migration of the version 0 keystore to version 1. Don't
	/// use it (it won't be staying around).
	/// <para>
	/// The document this implementation is based on can be found at
	/// <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html>
	/// RSA's PKCS12 Page</a>
	/// </para>
	/// </summary>
	public class OldPKCS12ParametersGenerator : PBEParametersGenerator
	{
		public const int KEY_MATERIAL = 1;
		public const int IV_MATERIAL = 2;
		public const int MAC_MATERIAL = 3;

		private Digest digest;

		private int u;
		private int v;

		/// <summary>
		/// Construct a PKCS 12 Parameters generator. This constructor will
		/// accept MD5, SHA1, and RIPEMD160.
		/// </summary>
		/// <param name="digest"> the digest to be used as the source of derived keys. </param>
		/// <exception cref="IllegalArgumentException"> if an unknown digest is passed in. </exception>
		public OldPKCS12ParametersGenerator(Digest digest)
		{
			this.digest = digest;
			if (digest is MD5Digest)
			{
				u = 128 / 8;
				v = 512 / 8;
			}
			else if (digest is SHA1Digest)
			{
				u = 160 / 8;
				v = 512 / 8;
			}
			else if (digest is RIPEMD160Digest)
			{
				u = 160 / 8;
				v = 512 / 8;
			}
			else
			{
				throw new IllegalArgumentException("Digest " + digest.getAlgorithmName() + " unsupported");
			}
		}

		/// <summary>
		/// add a + b + 1, returning the result in a. The a value is treated
		/// as a BigInteger of length (b.length * 8) bits. The result is 
		/// modulo 2^b.length in case of overflow.
		/// </summary>
		private void adjust(byte[] a, int aOff, byte[] b)
		{
			int x = (b[b.Length - 1] & 0xff) + (a[aOff + b.Length - 1] & 0xff) + 1;

			a[aOff + b.Length - 1] = (byte)x;
			x = (int)((uint)x >> 8);

			for (int i = b.Length - 2; i >= 0; i--)
			{
				x += (b[i] & 0xff) + (a[aOff + i] & 0xff);
				a[aOff + i] = (byte)x;
				x = (int)((uint)x >> 8);
			}
		}

		/// <summary>
		/// generation of a derived key ala PKCS12 V1.0.
		/// </summary>
		private byte[] generateDerivedKey(int idByte, int n)
		{
			byte[] D = new byte[v];
			byte[] dKey = new byte[n];

			for (int i = 0; i != D.Length; i++)
			{
				D[i] = (byte)idByte;
			}

			byte[] S;

			if ((salt != null) && (salt.Length != 0))
			{
				S = new byte[v * ((salt.Length + v - 1) / v)];

				for (int i = 0; i != S.Length; i++)
				{
					S[i] = salt[i % salt.Length];
				}
			}
			else
			{
				S = new byte[0];
			}

			byte[] P;

			if ((password != null) && (password.Length != 0))
			{
				P = new byte[v * ((password.Length + v - 1) / v)];

				for (int i = 0; i != P.Length; i++)
				{
					P[i] = password[i % password.Length];
				}
			}
			else
			{
				P = new byte[0];
			}

			byte[] I = new byte[S.Length + P.Length];

			JavaSystem.arraycopy(S, 0, I, 0, S.Length);
			JavaSystem.arraycopy(P, 0, I, S.Length, P.Length);

			byte[] B = new byte[v];
			int c = (n + u - 1) / u;

			for (int i = 1; i <= c; i++)
			{
				byte[] A = new byte[u];

				digest.update(D, 0, D.Length);
				digest.update(I, 0, I.Length);
				digest.doFinal(A, 0);
				for (int j = 1; j != iterationCount; j++)
				{
					digest.update(A, 0, A.Length);
					digest.doFinal(A, 0);
				}

				for (int j = 0; j != B.Length; j++)
				{
					B[i] = A[j % A.Length];
				}

				for (int j = 0; j != I.Length / v; j++)
				{
					adjust(I, j * v, B);
				}

				if (i == c)
				{
					JavaSystem.arraycopy(A, 0, dKey, (i - 1) * u, dKey.Length - ((i - 1) * u));
				}
				else
				{
					JavaSystem.arraycopy(A, 0, dKey, (i - 1) * u, A.Length);
				}
			}

			return dKey;
		}

		/// <summary>
		/// Generate a key parameter derived from the password, salt, and iteration
		/// count we are currently initialised with.
		/// </summary>
		/// <param name="keySize"> the size of the key we want (in bits) </param>
		/// <returns> a KeyParameter object. </returns>
		public override CipherParameters generateDerivedParameters(int keySize)
		{
			keySize = keySize / 8;

			byte[] dKey = generateDerivedKey(KEY_MATERIAL, keySize);

			return new KeyParameter(dKey, 0, keySize);
		}

		/// <summary>
		/// Generate a key with initialisation vector parameter derived from
		/// the password, salt, and iteration count we are currently initialised
		/// with.
		/// </summary>
		/// <param name="keySize"> the size of the key we want (in bits) </param>
		/// <param name="ivSize"> the size of the iv we want (in bits) </param>
		/// <returns> a ParametersWithIV object. </returns>
		public override CipherParameters generateDerivedParameters(int keySize, int ivSize)
		{
			keySize = keySize / 8;
			ivSize = ivSize / 8;

			byte[] dKey = generateDerivedKey(KEY_MATERIAL, keySize);

			byte[] iv = generateDerivedKey(IV_MATERIAL, ivSize);

			return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), iv, 0, ivSize);
		}

		/// <summary>
		/// Generate a key parameter for use with a MAC derived from the password,
		/// salt, and iteration count we are currently initialised with.
		/// </summary>
		/// <param name="keySize"> the size of the key we want (in bits) </param>
		/// <returns> a KeyParameter object. </returns>
		public override CipherParameters generateDerivedMacParameters(int keySize)
		{
			keySize = keySize / 8;

			byte[] dKey = generateDerivedKey(MAC_MATERIAL, keySize);

			return new KeyParameter(dKey, 0, keySize);
		}
	}

	public interface BrokenPBE
	{
		//
		// PBE Based encryption constants - by default we do PKCS12 with SHA-1
		//

		/// <summary>
		/// uses the appropriate mixer to generate the key and IV if neccessary.
		/// </summary>
	}

	public static class BrokenPBE_Fields
	{
		public const int MD5 = 0;
		public const int SHA1 = 1;
		public const int RIPEMD160 = 2;
		public const int PKCS5S1 = 0;
		public const int PKCS5S2 = 1;
		public const int PKCS12 = 2;
		public const int OLD_PKCS12 = 3;
	}

	public class BrokenPBE_Util
	{
		/// <summary>
		/// a faulty parity routine...
		/// </summary>
		/// <param name="bytes"> the byte array to set the parity on. </param>
		internal static void setOddParity(byte[] bytes)
		{
			for (int i = 0; i < bytes.Length; i++)
			{
				int b = bytes[i];
				bytes[i] = unchecked((byte)((b & 0xfe) | (((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01)));
			}
		}

		internal static PBEParametersGenerator makePBEGenerator(int type, int hash)
		{
			PBEParametersGenerator generator;

			if (type == BrokenPBE_Fields.PKCS5S1)
			{
				switch (hash)
				{
				case BrokenPBE_Fields.MD5:
					generator = new PKCS5S1ParametersGenerator(new MD5Digest());
					break;
				case BrokenPBE_Fields.SHA1:
					generator = new PKCS5S1ParametersGenerator(new SHA1Digest());
					break;
				default:
					throw new IllegalStateException("PKCS5 scheme 1 only supports only MD5 and SHA1.");
				}
			}
			else if (type == BrokenPBE_Fields.PKCS5S2)
			{
				generator = new PKCS5S2ParametersGenerator();
			}
			else if (type == BrokenPBE_Fields.OLD_PKCS12)
			{
				switch (hash)
				{
				case BrokenPBE_Fields.MD5:
					generator = new OldPKCS12ParametersGenerator(new MD5Digest());
					break;
				case BrokenPBE_Fields.SHA1:
					generator = new OldPKCS12ParametersGenerator(new SHA1Digest());
					break;
				case BrokenPBE_Fields.RIPEMD160:
					generator = new OldPKCS12ParametersGenerator(new RIPEMD160Digest());
					break;
				default:
					throw new IllegalStateException("unknown digest scheme for PBE encryption.");
				}
			}
			else
			{
				switch (hash)
				{
				case BrokenPBE_Fields.MD5:
					generator = new PKCS12ParametersGenerator(new MD5Digest());
					break;
				case BrokenPBE_Fields.SHA1:
					generator = new PKCS12ParametersGenerator(new SHA1Digest());
					break;
				case BrokenPBE_Fields.RIPEMD160:
					generator = new PKCS12ParametersGenerator(new RIPEMD160Digest());
					break;
				default:
					throw new IllegalStateException("unknown digest scheme for PBE encryption.");
				}
			}

			return generator;
		}

		/// <summary>
		/// construct a key and iv (if neccessary) suitable for use with a 
		/// Cipher.
		/// </summary>
		internal static CipherParameters makePBEParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec, int type, int hash, string targetAlgorithm, int keySize, int ivSize)
		{
			if ((spec == null) || !(spec is PBEParameterSpec))
			{
				throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
			}

			PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
			PBEParametersGenerator generator = makePBEGenerator(type, hash);
			byte[] key = pbeKey.getEncoded();
			CipherParameters param;

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

					setOddParity(kParam.getKey());
				}
				else
				{
					KeyParameter kParam = (KeyParameter)param;

					setOddParity(kParam.getKey());
				}
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
		internal static CipherParameters makePBEMacParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec, int type, int hash, int keySize)
		{
			if ((spec == null) || !(spec is PBEParameterSpec))
			{
				throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
			}

			PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
			PBEParametersGenerator generator = makePBEGenerator(type, hash);
			byte[] key = pbeKey.getEncoded();
			CipherParameters param;

			generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

			param = generator.generateDerivedMacParameters(keySize);

			for (int i = 0; i != key.Length; i++)
			{
				key[i] = 0;
			}

			return param;
		}
	}

}