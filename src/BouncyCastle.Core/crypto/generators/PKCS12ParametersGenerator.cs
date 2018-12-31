using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
		
	/// <summary>
	/// Generator for PBE derived keys and ivs as defined by PKCS 12 V1.0.
	/// <para>
	/// The document this implementation is based on can be found at
	/// <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html>
	/// RSA's PKCS12 Page</a>
	/// </para>
	/// </summary>
	public class PKCS12ParametersGenerator : PBEParametersGenerator
	{
		public const int KEY_MATERIAL = 1;
		public const int IV_MATERIAL = 2;
		public const int MAC_MATERIAL = 3;

		private Digest digest;

		private int u;
		private int v;

		/// <summary>
		/// Construct a PKCS 12 Parameters generator. This constructor will
		/// accept any digest which also implements ExtendedDigest.
		/// </summary>
		/// <param name="digest"> the digest to be used as the source of derived keys. </param>
		/// <exception cref="IllegalArgumentException"> if an unknown digest is passed in. </exception>
		public PKCS12ParametersGenerator(Digest digest)
		{
			this.digest = digest;
			if (digest is ExtendedDigest)
			{
				u = digest.getDigestSize();
				v = ((ExtendedDigest)digest).getByteLength();
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
			byte[] A = new byte[u];

			for (int i = 1; i <= c; i++)
			{
				digest.update(D, 0, D.Length);
				digest.update(I, 0, I.Length);
				digest.doFinal(A, 0);
				for (int j = 1; j < iterationCount; j++)
				{
					digest.update(A, 0, A.Length);
					digest.doFinal(A, 0);
				}

				for (int j = 0; j != B.Length; j++)
				{
					B[j] = A[j % A.Length];
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

}