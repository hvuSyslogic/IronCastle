using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
			
	/// <summary>
	/// Generator for PBE derived keys and ivs as usd by OpenSSL.
	/// <para>
	/// The scheme is a simple extension of PKCS 5 V2.0 Scheme 1 using MD5 with an
	/// iteration count of 1.
	/// </para>
	/// <para>
	/// </para>
	/// </summary>
	public class OpenSSLPBEParametersGenerator : PBEParametersGenerator
	{
		private Digest digest = DigestFactory.createMD5();

		/// <summary>
		/// Construct a OpenSSL Parameters generator. 
		/// </summary>
		public OpenSSLPBEParametersGenerator()
		{
		}

		/// <summary>
		/// Initialise - note the iteration count for this algorithm is fixed at 1.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="salt"> salt to use. </param>
		public virtual void init(byte[] password, byte[] salt)
		{
			base.init(password, salt, 1);
		}

		/// <summary>
		/// the derived key function, the ith hash of the password and the salt.
		/// </summary>
		private byte[] generateDerivedKey(int bytesNeeded)
		{
			byte[] buf = new byte[digest.getDigestSize()];
			byte[] key = new byte[bytesNeeded];
			int offset = 0;

			for (;;)
			{
				digest.update(password, 0, password.Length);
				digest.update(salt, 0, salt.Length);

				digest.doFinal(buf, 0);

				int len = (bytesNeeded > buf.Length) ? buf.Length : bytesNeeded;
				JavaSystem.arraycopy(buf, 0, key, offset, len);
				offset += len;

				// check if we need any more
				bytesNeeded -= len;
				if (bytesNeeded == 0)
				{
					break;
				}

				// do another round
				digest.reset();
				digest.update(buf, 0, buf.Length);
			}

			return key;
		}

		/// <summary>
		/// Generate a key parameter derived from the password, salt, and iteration
		/// count we are currently initialised with.
		/// </summary>
		/// <param name="keySize"> the size of the key we want (in bits) </param>
		/// <returns> a KeyParameter object. </returns>
		/// <exception cref="IllegalArgumentException"> if the key length larger than the base hash size. </exception>
		public override CipherParameters generateDerivedParameters(int keySize)
		{
			keySize = keySize / 8;

			byte[] dKey = generateDerivedKey(keySize);

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
		/// <exception cref="IllegalArgumentException"> if keySize + ivSize is larger than the base hash size. </exception>
		public override CipherParameters generateDerivedParameters(int keySize, int ivSize)
		{
			keySize = keySize / 8;
			ivSize = ivSize / 8;

			byte[] dKey = generateDerivedKey(keySize + ivSize);

			return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), dKey, keySize, ivSize);
		}

		/// <summary>
		/// Generate a key parameter for use with a MAC derived from the password,
		/// salt, and iteration count we are currently initialised with.
		/// </summary>
		/// <param name="keySize"> the size of the key we want (in bits) </param>
		/// <returns> a KeyParameter object. </returns>
		/// <exception cref="IllegalArgumentException"> if the key length larger than the base hash size. </exception>
		public override CipherParameters generateDerivedMacParameters(int keySize)
		{
			return generateDerivedParameters(keySize);
		}
	}

}