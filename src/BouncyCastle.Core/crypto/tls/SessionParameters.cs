using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;

	public sealed class SessionParameters
	{
		public sealed class Builder
		{
			internal int cipherSuite = -1;
			internal short compressionAlgorithm = -1;
			internal byte[] masterSecret = null;
			internal Certificate peerCertificate = null;
			internal byte[] pskIdentity = null;
			internal byte[] srpIdentity = null;
			internal byte[] encodedServerExtensions = null;
			internal bool extendedMasterSecret = false;

			public Builder()
			{
			}

			public SessionParameters build()
			{
				validate(this.cipherSuite >= 0, "cipherSuite");
				validate(this.compressionAlgorithm >= 0, "compressionAlgorithm");
				validate(this.masterSecret != null, "masterSecret");
				return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate, pskIdentity, srpIdentity, encodedServerExtensions, extendedMasterSecret);
			}

			public Builder setCipherSuite(int cipherSuite)
			{
				this.cipherSuite = cipherSuite;
				return this;
			}

			public Builder setCompressionAlgorithm(short compressionAlgorithm)
			{
				this.compressionAlgorithm = compressionAlgorithm;
				return this;
			}

			public Builder setExtendedMasterSecret(bool extendedMasterSecret)
			{
				this.extendedMasterSecret = extendedMasterSecret;
				return this;
			}

			public Builder setMasterSecret(byte[] masterSecret)
			{
				this.masterSecret = masterSecret;
				return this;
			}

			public Builder setPeerCertificate(Certificate peerCertificate)
			{
				this.peerCertificate = peerCertificate;
				return this;
			}

			/// @deprecated Use <seealso cref="#setPSKIdentity(byte[])"/> 
			public Builder setPskIdentity(byte[] pskIdentity)
			{
				this.pskIdentity = pskIdentity;
				return this;
			}

			public Builder setPSKIdentity(byte[] pskIdentity)
			{
				this.pskIdentity = pskIdentity;
				return this;
			}

			public Builder setSRPIdentity(byte[] srpIdentity)
			{
				this.srpIdentity = srpIdentity;
				return this;
			}

			public Builder setServerExtensions(Hashtable serverExtensions)
			{
				if (serverExtensions == null)
				{
					encodedServerExtensions = null;
				}
				else
				{
					ByteArrayOutputStream buf = new ByteArrayOutputStream();
					TlsProtocol.writeExtensions(buf, serverExtensions);
					encodedServerExtensions = buf.toByteArray();
				}
				return this;
			}

			public void validate(bool condition, string parameter)
			{
				if (!condition)
				{
					throw new IllegalStateException("Required session parameter '" + parameter + "' not configured");
				}
			}
		}

		private int cipherSuite;
		private short compressionAlgorithm;
		private byte[] masterSecret;
		private Certificate peerCertificate;
		private byte[] pskIdentity = null;
		private byte[] srpIdentity = null;
		private byte[] encodedServerExtensions;
		private bool extendedMasterSecret;

		private SessionParameters(int cipherSuite, short compressionAlgorithm, byte[] masterSecret, Certificate peerCertificate, byte[] pskIdentity, byte[] srpIdentity, byte[] encodedServerExtensions, bool extendedMasterSecret)
		{
			this.cipherSuite = cipherSuite;
			this.compressionAlgorithm = compressionAlgorithm;
			this.masterSecret = Arrays.clone(masterSecret);
			this.peerCertificate = peerCertificate;
			this.pskIdentity = Arrays.clone(pskIdentity);
			this.srpIdentity = Arrays.clone(srpIdentity);
			this.encodedServerExtensions = encodedServerExtensions;
			this.extendedMasterSecret = extendedMasterSecret;
		}

		public void clear()
		{
			if (this.masterSecret != null)
			{
				Arrays.fill(this.masterSecret, 0);
			}
		}

		public SessionParameters copy()
		{
			return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate, pskIdentity, srpIdentity, encodedServerExtensions, extendedMasterSecret);
		}

		public int getCipherSuite()
		{
			return cipherSuite;
		}

		public short getCompressionAlgorithm()
		{
			return compressionAlgorithm;
		}

		public byte[] getMasterSecret()
		{
			return masterSecret;
		}

		public Certificate getPeerCertificate()
		{
			return peerCertificate;
		}

		/// @deprecated Use <seealso cref="#getPSKIdentity()"/> 
		public byte[] getPskIdentity()
		{
			return pskIdentity;
		}

		public byte[] getPSKIdentity()
		{
			return pskIdentity;
		}

		public byte[] getSRPIdentity()
		{
			return srpIdentity;
		}

		public bool isExtendedMasterSecret()
		{
			return extendedMasterSecret;
		}

		public Hashtable readServerExtensions()
		{
			if (encodedServerExtensions == null)
			{
				return null;
			}

			ByteArrayInputStream buf = new ByteArrayInputStream(encodedServerExtensions);
			return TlsProtocol.readExtensions(buf);
		}
	}

}