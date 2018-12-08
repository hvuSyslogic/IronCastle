using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	using DigestRandomGenerator = org.bouncycastle.crypto.prng.DigestRandomGenerator;
	using RandomGenerator = org.bouncycastle.crypto.prng.RandomGenerator;
	using Times = org.bouncycastle.util.Times;

	public abstract class AbstractTlsContext : TlsContext
	{
		public abstract bool isServer();
		private static long counter = Times.nanoTime();

		private static long nextCounterValue()
		{
			lock (typeof(AbstractTlsContext))
			{
				return ++counter;
			}
		}

		private RandomGenerator nonceRandom;
		private SecureRandom secureRandom;
		private SecurityParameters securityParameters;

		private ProtocolVersion clientVersion = null;
		private ProtocolVersion serverVersion = null;
		private TlsSession session = null;
		private object userObject = null;

		public AbstractTlsContext(SecureRandom secureRandom, SecurityParameters securityParameters)
		{
			Digest d = TlsUtils.createHash(HashAlgorithm.sha256);
			byte[] seed = new byte[d.getDigestSize()];
			secureRandom.nextBytes(seed);

			this.nonceRandom = new DigestRandomGenerator(d);
			nonceRandom.addSeedMaterial(nextCounterValue());
			nonceRandom.addSeedMaterial(Times.nanoTime());
			nonceRandom.addSeedMaterial(seed);

			this.secureRandom = secureRandom;
			this.securityParameters = securityParameters;
		}

		public virtual RandomGenerator getNonceRandomGenerator()
		{
			return nonceRandom;
		}

		public virtual SecureRandom getSecureRandom()
		{
			return secureRandom;
		}

		public virtual SecurityParameters getSecurityParameters()
		{
			return securityParameters;
		}

		public virtual ProtocolVersion getClientVersion()
		{
			return clientVersion;
		}

		public virtual void setClientVersion(ProtocolVersion clientVersion)
		{
			this.clientVersion = clientVersion;
		}

		public virtual ProtocolVersion getServerVersion()
		{
			return serverVersion;
		}

		public virtual void setServerVersion(ProtocolVersion serverVersion)
		{
			this.serverVersion = serverVersion;
		}

		public virtual TlsSession getResumableSession()
		{
			return session;
		}

		public virtual void setResumableSession(TlsSession session)
		{
			this.session = session;
		}

		public virtual object getUserObject()
		{
			return userObject;
		}

		public virtual void setUserObject(object userObject)
		{
			this.userObject = userObject;
		}

		public virtual byte[] exportKeyingMaterial(string asciiLabel, byte[] context_value, int length)
		{
			if (context_value != null && !TlsUtils.isValidUint16(context_value.Length))
			{
				throw new IllegalArgumentException("'context_value' must have length less than 2^16 (or be null)");
			}

			SecurityParameters sp = getSecurityParameters();
			if (!sp.isExtendedMasterSecret())
			{
				/*
				 * RFC 7627 5.4. If a client or server chooses to continue with a full handshake without
				 * the extended master secret extension, [..] the client or server MUST NOT export any
				 * key material based on the new master secret for any subsequent application-level
				 * authentication. In particular, it MUST disable [RFC5705] [..].
				 */
				throw new IllegalStateException("cannot export keying material without extended_master_secret");
			}

			byte[] cr = sp.getClientRandom(), sr = sp.getServerRandom();

			int seedLength = cr.Length + sr.Length;
			if (context_value != null)
			{
				seedLength += (2 + context_value.Length);
			}

			byte[] seed = new byte[seedLength];
			int seedPos = 0;

			JavaSystem.arraycopy(cr, 0, seed, seedPos, cr.Length);
			seedPos += cr.Length;
			JavaSystem.arraycopy(sr, 0, seed, seedPos, sr.Length);
			seedPos += sr.Length;
			if (context_value != null)
			{
				TlsUtils.writeUint16(context_value.Length, seed, seedPos);
				seedPos += 2;
				JavaSystem.arraycopy(context_value, 0, seed, seedPos, context_value.Length);
				seedPos += context_value.Length;
			}

			if (seedPos != seedLength)
			{
				throw new IllegalStateException("error in calculation of seed for export");
			}

			return TlsUtils.PRF(this, sp.getMasterSecret(), asciiLabel, seed, length);
		}
	}

}