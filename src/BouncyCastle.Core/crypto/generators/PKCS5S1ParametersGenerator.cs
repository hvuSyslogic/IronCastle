using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
		
	/// <summary>
	/// Generator for PBE derived keys and ivs as defined by PKCS 5 V2.0 Scheme 1.
	/// Note this generator is limited to the size of the hash produced by the
	/// digest used to drive it.
	/// <para>
	/// The document this implementation is based on can be found at
	/// <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
	/// RSA's PKCS5 Page</a>
	/// </para>
	/// </summary>
	public class PKCS5S1ParametersGenerator : PBEParametersGenerator
	{
		private Digest digest;

		/// <summary>
		/// Construct a PKCS 5 Scheme 1 Parameters generator. 
		/// </summary>
		/// <param name="digest"> the digest to be used as the source of derived keys. </param>
		public PKCS5S1ParametersGenerator(Digest digest)
		{
			this.digest = digest;
		}

		/// <summary>
		/// the derived key function, the ith hash of the password and the salt.
		/// </summary>
		private byte[] generateDerivedKey()
		{
			byte[] digestBytes = new byte[digest.getDigestSize()];

			digest.update(password, 0, password.Length);
			digest.update(salt, 0, salt.Length);

			digest.doFinal(digestBytes, 0);
			for (int i = 1; i < iterationCount; i++)
			{
				digest.update(digestBytes, 0, digestBytes.Length);
				digest.doFinal(digestBytes, 0);
			}

			return digestBytes;
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

			if (keySize > digest.getDigestSize())
			{
				throw new IllegalArgumentException("Can't generate a derived key " + keySize + " bytes long.");
			}

			byte[] dKey = generateDerivedKey();

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

			if ((keySize + ivSize) > digest.getDigestSize())
			{
				throw new IllegalArgumentException("Can't generate a derived key " + (keySize + ivSize) + " bytes long.");
			}

			byte[] dKey = generateDerivedKey();

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