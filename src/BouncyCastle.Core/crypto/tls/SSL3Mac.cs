namespace org.bouncycastle.crypto.tls
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// HMAC implementation based on original internet draft for HMAC (RFC 2104)
	/// <para>
	/// The difference is that padding is concatenated versus XORed with the key
	/// </para>
	/// <para>
	/// H(K + opad, H(K + ipad, text))
	/// </para>
	/// </summary>
	public class SSL3Mac : Mac
	{
		private static readonly byte IPAD_BYTE = 0x36;
		private static readonly byte OPAD_BYTE = 0x5C;

		internal static readonly byte[] IPAD = genPad(IPAD_BYTE, 48);
		internal static readonly byte[] OPAD = genPad(OPAD_BYTE, 48);

		private Digest digest;
		private int padLength;

		private byte[] secret;

		/// <summary>
		/// Base constructor for one of the standard digest algorithms that the byteLength of
		/// the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
		/// </summary>
		/// <param name="digest"> the digest. </param>
		public SSL3Mac(Digest digest)
		{
			this.digest = digest;

			if (digest.getDigestSize() == 20)
			{
				this.padLength = 40;
			}
			else
			{
				this.padLength = 48;
			}
		}

		public virtual string getAlgorithmName()
		{
			return digest.getAlgorithmName() + "/SSL3MAC";
		}

		public virtual Digest getUnderlyingDigest()
		{
			return digest;
		}

		public virtual void init(CipherParameters @params)
		{
			secret = Arrays.clone(((KeyParameter)@params).getKey());

			reset();
		}

		public virtual int getMacSize()
		{
			return digest.getDigestSize();
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
			byte[] tmp = new byte[digest.getDigestSize()];
			digest.doFinal(tmp, 0);

			digest.update(secret, 0, secret.Length);
			digest.update(OPAD, 0, padLength);
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
			digest.reset();
			digest.update(secret, 0, secret.Length);
			digest.update(IPAD, 0, padLength);
		}

		private static byte[] genPad(byte b, int count)
		{
			byte[] padding = new byte[count];
			Arrays.fill(padding, b);
			return padding;
		}
	}

}