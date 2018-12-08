using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// A combined hash, which implements md5(m) || sha1(m).
	/// </summary>
	public class CombinedHash : TlsHandshakeHash
	{
		protected internal TlsContext context;
		protected internal Digest md5;
		protected internal Digest sha1;

		public CombinedHash()
		{
			this.md5 = TlsUtils.createHash(HashAlgorithm.md5);
			this.sha1 = TlsUtils.createHash(HashAlgorithm.sha1);
		}

		public CombinedHash(CombinedHash t)
		{
			this.context = t.context;
			this.md5 = TlsUtils.cloneHash(HashAlgorithm.md5, t.md5);
			this.sha1 = TlsUtils.cloneHash(HashAlgorithm.sha1, t.sha1);
		}

		public virtual void init(TlsContext context)
		{
			this.context = context;
		}

		public virtual TlsHandshakeHash notifyPRFDetermined()
		{
			return this;
		}

		public virtual void trackHashAlgorithm(short hashAlgorithm)
		{
			throw new IllegalStateException("CombinedHash only supports calculating the legacy PRF for handshake hash");
		}

		public virtual void sealHashAlgorithms()
		{
		}

		public virtual TlsHandshakeHash stopTracking()
		{
			return new CombinedHash(this);
		}

		public virtual Digest forkPRFHash()
		{
			return new CombinedHash(this);
		}

		public virtual byte[] getFinalHash(short hashAlgorithm)
		{
			throw new IllegalStateException("CombinedHash doesn't support multiple hashes");
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#getAlgorithmName() </seealso>
		public virtual string getAlgorithmName()
		{
			return md5.getAlgorithmName() + " and " + sha1.getAlgorithmName();
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#getDigestSize() </seealso>
		public virtual int getDigestSize()
		{
			return md5.getDigestSize() + sha1.getDigestSize();
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#update(byte) </seealso>
		public virtual void update(byte input)
		{
			md5.update(input);
			sha1.update(input);
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#update(byte[], int, int) </seealso>
		public virtual void update(byte[] input, int inOff, int len)
		{
			md5.update(input, inOff, len);
			sha1.update(input, inOff, len);
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#doFinal(byte[], int) </seealso>
		public virtual int doFinal(byte[] output, int outOff)
		{
			if (context != null && TlsUtils.isSSL(context))
			{
				ssl3Complete(md5, SSL3Mac.IPAD, SSL3Mac.OPAD, 48);
				ssl3Complete(sha1, SSL3Mac.IPAD, SSL3Mac.OPAD, 40);
			}

			int i1 = md5.doFinal(output, outOff);
			int i2 = sha1.doFinal(output, outOff + i1);
			return i1 + i2;
		}

		/// <seealso cref= org.bouncycastle.crypto.Digest#reset() </seealso>
		public virtual void reset()
		{
			md5.reset();
			sha1.reset();
		}

		public virtual void ssl3Complete(Digest d, byte[] ipad, byte[] opad, int padLength)
		{
			byte[] master_secret = context.getSecurityParameters().masterSecret;

			d.update(master_secret, 0, master_secret.Length);
			d.update(ipad, 0, padLength);

			byte[] tmp = new byte[d.getDigestSize()];
			d.doFinal(tmp, 0);

			d.update(master_secret, 0, master_secret.Length);
			d.update(opad, 0, padLength);
			d.update(tmp, 0, tmp.Length);
		}
	}

}