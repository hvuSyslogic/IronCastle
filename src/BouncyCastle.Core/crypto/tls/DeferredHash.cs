using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.tls
{

	
	/// <summary>
	/// Buffers input until the hash algorithm is determined.
	/// </summary>
	public class DeferredHash : TlsHandshakeHash
	{
		protected internal const int BUFFERING_HASH_LIMIT = 4;

		protected internal TlsContext context;

		private DigestInputBuffer buf;
		private Hashtable hashes;
		private short? prfHashAlgorithm;

		public DeferredHash()
		{
			this.buf = new DigestInputBuffer();
			this.hashes = new Hashtable();
			this.prfHashAlgorithm = null;
		}

		private DeferredHash(short? prfHashAlgorithm, Digest prfHash)
		{
			this.buf = null;
			this.hashes = new Hashtable();
			this.prfHashAlgorithm = prfHashAlgorithm;
			hashes.put(prfHashAlgorithm, prfHash);
		}

		public virtual void init(TlsContext context)
		{
			this.context = context;
		}

		public virtual TlsHandshakeHash notifyPRFDetermined()
		{
			int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
			if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
			{
				CombinedHash legacyHash = new CombinedHash();
				legacyHash.init(context);
				buf.updateDigest(legacyHash);
				return legacyHash.notifyPRFDetermined();
			}

			this.prfHashAlgorithm = Shorts.valueOf(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));

			checkTrackingHash(prfHashAlgorithm);

			return this;
		}

		public virtual void trackHashAlgorithm(short hashAlgorithm)
		{
			if (buf == null)
			{
				throw new IllegalStateException("Too late to track more hash algorithms");
			}

			checkTrackingHash(Shorts.valueOf(hashAlgorithm));
		}

		public virtual void sealHashAlgorithms()
		{
			checkStopBuffering();
		}

		public virtual TlsHandshakeHash stopTracking()
		{
			Digest prfHash = TlsUtils.cloneHash(prfHashAlgorithm.Value, (Digest)hashes.get(prfHashAlgorithm));
			if (buf != null)
			{
				buf.updateDigest(prfHash);
			}
			DeferredHash result = new DeferredHash(prfHashAlgorithm, prfHash);
			result.init(context);
			return result;
		}

		public virtual Digest forkPRFHash()
		{
			checkStopBuffering();

			if (buf != null)
			{
				Digest prfHash = TlsUtils.createHash(prfHashAlgorithm.Value);
				buf.updateDigest(prfHash);
				return prfHash;
			}

			return TlsUtils.cloneHash(prfHashAlgorithm.Value, (Digest)hashes.get(prfHashAlgorithm));
		}

		public virtual byte[] getFinalHash(short hashAlgorithm)
		{
			Digest d = (Digest)hashes.get(Shorts.valueOf(hashAlgorithm));
			if (d == null)
			{
				throw new IllegalStateException("HashAlgorithm." + HashAlgorithm.getText(hashAlgorithm) + " is not being tracked");
			}

			d = TlsUtils.cloneHash(hashAlgorithm, d);
			if (buf != null)
			{
				buf.updateDigest(d);
			}

			byte[] bs = new byte[d.getDigestSize()];
			d.doFinal(bs, 0);
			return bs;
		}

		public virtual string getAlgorithmName()
		{
			throw new IllegalStateException("Use fork() to get a definite Digest");
		}

		public virtual int getDigestSize()
		{
			throw new IllegalStateException("Use fork() to get a definite Digest");
		}

		public virtual void update(byte input)
		{
			if (buf != null)
			{
				buf.write(input);
				return;
			}

			Enumeration e = hashes.elements();
			while (e.hasMoreElements())
			{
				Digest hash = (Digest)e.nextElement();
				hash.update(input);
			}
		}

		public virtual void update(byte[] input, int inOff, int len)
		{
			if (buf != null)
			{
				buf.write(input, inOff, len);
				return;
			}

			Enumeration e = hashes.elements();
			while (e.hasMoreElements())
			{
				Digest hash = (Digest)e.nextElement();
				hash.update(input, inOff, len);
			}
		}

		public virtual int doFinal(byte[] output, int outOff)
		{
			throw new IllegalStateException("Use fork() to get a definite Digest");
		}

		public virtual void reset()
		{
			if (buf != null)
			{
				buf.reset();
				return;
			}

			Enumeration e = hashes.elements();
			while (e.hasMoreElements())
			{
				Digest hash = (Digest)e.nextElement();
				hash.reset();
			}
		}

		public virtual void checkStopBuffering()
		{
			if (buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
			{
				Enumeration e = hashes.elements();
				while (e.hasMoreElements())
				{
					Digest hash = (Digest)e.nextElement();
					buf.updateDigest(hash);
				}

				this.buf = null;
			}
		}

		public virtual void checkTrackingHash(short? hashAlgorithm)
		{
			if (!hashes.containsKey(hashAlgorithm))
			{
				Digest hash = TlsUtils.createHash(hashAlgorithm.Value);
				hashes.put(hashAlgorithm, hash);
			}
		}
	}

}