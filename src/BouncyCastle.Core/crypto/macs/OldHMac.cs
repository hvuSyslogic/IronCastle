using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.macs
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	/// <summary>
	/// HMAC implementation based on RFC2104
	/// 
	/// H(K XOR opad, H(K XOR ipad, text))
	/// </summary>
	public class OldHMac : Mac
	{
		private const int BLOCK_LENGTH = 64;

		private static readonly byte IPAD = (byte)0x36;
		private static readonly byte OPAD = (byte)0x5C;

		private Digest digest;
		private int digestSize;
		private byte[] inputPad = new byte[BLOCK_LENGTH];
		private byte[] outputPad = new byte[BLOCK_LENGTH];

		/// @deprecated uses incorrect pad for SHA-512 and SHA-384 use HMac. 
		public OldHMac(Digest digest)
		{
			this.digest = digest;
			digestSize = digest.getDigestSize();
		}

		public virtual string getAlgorithmName()
		{
			return digest.getAlgorithmName() + "/HMAC";
		}

		public virtual Digest getUnderlyingDigest()
		{
			return digest;
		}

		public virtual void init(CipherParameters @params)
		{
			digest.reset();

			byte[] key = ((KeyParameter)@params).getKey();

			if (key.Length > BLOCK_LENGTH)
			{
				digest.update(key, 0, key.Length);
				digest.doFinal(inputPad, 0);
				for (int i = digestSize; i < inputPad.Length; i++)
				{
					inputPad[i] = 0;
				}
			}
			else
			{
				JavaSystem.arraycopy(key, 0, inputPad, 0, key.Length);
				for (int i = key.Length; i < inputPad.Length; i++)
				{
					inputPad[i] = 0;
				}
			}

			outputPad = new byte[inputPad.Length];
			JavaSystem.arraycopy(inputPad, 0, outputPad, 0, inputPad.Length);

			for (int i = 0; i < inputPad.Length; i++)
			{
				inputPad[i] ^= IPAD;
			}

			for (int i = 0; i < outputPad.Length; i++)
			{
				outputPad[i] ^= OPAD;
			}

			digest.update(inputPad, 0, inputPad.Length);
		}

		public virtual int getMacSize()
		{
			return digestSize;
		}

		public virtual void update(byte @in)
		{
			digest.update(@in);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			digest.update(@in, inOff, len);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			byte[] tmp = new byte[digestSize];
			digest.doFinal(tmp, 0);

			digest.update(outputPad, 0, outputPad.Length);
			digest.update(tmp, 0, tmp.Length);

			int len = digest.doFinal(@out, outOff);

			reset();

			return len;
		}

		/// <summary>
		/// Reset the mac generator.
		/// </summary>
		public virtual void reset()
		{
			/*
			 * reset the underlying digest.
			 */
			digest.reset();

			/*
			 * reinitialize the digest.
			 */
			digest.update(inputPad, 0, inputPad.Length);
		}
	}

}