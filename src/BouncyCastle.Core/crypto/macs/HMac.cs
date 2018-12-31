using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.macs
{

			
	/// <summary>
	/// HMAC implementation based on RFC2104
	/// 
	/// H(K XOR opad, H(K XOR ipad, text))
	/// </summary>
	public class HMac : Mac
	{
		private static readonly byte IPAD = 0x36;
		private static readonly byte OPAD = 0x5C;

		private Digest digest;
		private int digestSize;
		private int blockLength;
		private Memoable ipadState;
		private Memoable opadState;

		private byte[] inputPad;
		private byte[] outputBuf;

		private static Hashtable blockLengths;

		static HMac()
		{
			blockLengths = new Hashtable();

			blockLengths.put("GOST3411", Integers.valueOf(32));

			blockLengths.put("MD2", Integers.valueOf(16));
			blockLengths.put("MD4", Integers.valueOf(64));
			blockLengths.put("MD5", Integers.valueOf(64));

			blockLengths.put("RIPEMD128", Integers.valueOf(64));
			blockLengths.put("RIPEMD160", Integers.valueOf(64));

			blockLengths.put("SHA-1", Integers.valueOf(64));
			blockLengths.put("SHA-224", Integers.valueOf(64));
			blockLengths.put("SHA-256", Integers.valueOf(64));
			blockLengths.put("SHA-384", Integers.valueOf(128));
			blockLengths.put("SHA-512", Integers.valueOf(128));

			blockLengths.put("Tiger", Integers.valueOf(64));
			blockLengths.put("Whirlpool", Integers.valueOf(64));
		}

		private static int getByteLength(Digest digest)
		{
			if (digest is ExtendedDigest)
			{
				return ((ExtendedDigest)digest).getByteLength();
			}

			int? b = (int?)blockLengths.get(digest.getAlgorithmName());

			if (b == null)
			{
				throw new IllegalArgumentException("unknown digest passed: " + digest.getAlgorithmName());
			}

			return b.Value;
		}

		/// <summary>
		/// Base constructor for one of the standard digest algorithms that the 
		/// byteLength of the algorithm is know for.
		/// </summary>
		/// <param name="digest"> the digest. </param>
		public HMac(Digest digest) : this(digest, getByteLength(digest))
		{
		}

		private HMac(Digest digest, int byteLength)
		{
			this.digest = digest;
			this.digestSize = digest.getDigestSize();
			this.blockLength = byteLength;
			this.inputPad = new byte[blockLength];
			this.outputBuf = new byte[blockLength + digestSize];
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
			int keyLength = key.Length;

			if (keyLength > blockLength)
			{
				digest.update(key, 0, keyLength);
				digest.doFinal(inputPad, 0);

				keyLength = digestSize;
			}
			else
			{
				JavaSystem.arraycopy(key, 0, inputPad, 0, keyLength);
			}

			for (int i = keyLength; i < inputPad.Length; i++)
			{
				inputPad[i] = 0;
			}

			JavaSystem.arraycopy(inputPad, 0, outputBuf, 0, blockLength);

			xorPad(inputPad, blockLength, IPAD);
			xorPad(outputBuf, blockLength, OPAD);

			if (digest is Memoable)
			{
				opadState = ((Memoable)digest).copy();

				((Digest)opadState).update(outputBuf, 0, blockLength);
			}

			digest.update(inputPad, 0, inputPad.Length);

			if (digest is Memoable)
			{
				ipadState = ((Memoable)digest).copy();
			}
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
			digest.doFinal(outputBuf, blockLength);

			if (opadState != null)
			{
				((Memoable)digest).reset(opadState);
				digest.update(outputBuf, blockLength, digest.getDigestSize());
			}
			else
			{
				digest.update(outputBuf, 0, outputBuf.Length);
			}

			int len = digest.doFinal(@out, outOff);

			for (int i = blockLength; i < outputBuf.Length; i++)
			{
				outputBuf[i] = 0;
			}

			if (ipadState != null)
			{
				((Memoable)digest).reset(ipadState);
			}
			else
			{
				digest.update(inputPad, 0, inputPad.Length);
			}

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

		private static void xorPad(byte[] pad, int len, byte n)
		{
			for (int i = 0; i < len; ++i)
			{
				pad[i] ^= n;
			}
		}
	}

}