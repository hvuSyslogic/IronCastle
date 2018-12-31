namespace org.bouncycastle.crypto.tls
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecurityParameters
	{
		internal int entity = -1;
		internal int cipherSuite = -1;
		internal short compressionAlgorithm = CompressionMethod._null;
		internal int prfAlgorithm = -1;
		internal int verifyDataLength = -1;
		internal byte[] masterSecret = null;
		internal byte[] clientRandom = null;
		internal byte[] serverRandom = null;
		internal byte[] sessionHash = null;
		internal byte[] pskIdentity = null;
		internal byte[] srpIdentity = null;

		// TODO Keep these internal, since it's maybe not the ideal place for them
		internal short maxFragmentLength = -1;
		internal bool truncatedHMac = false;
		internal bool encryptThenMAC = false;
		internal bool extendedMasterSecret = false;

		public virtual void clear()
		{
			if (this.masterSecret != null)
			{
				Arrays.fill(this.masterSecret, 0);
				this.masterSecret = null;
			}
		}

		/// <returns> <seealso cref="ConnectionEnd"/> </returns>
		public virtual int getEntity()
		{
			return entity;
		}

		/// <returns> <seealso cref="CipherSuite"/> </returns>
		public virtual int getCipherSuite()
		{
			return cipherSuite;
		}

		/// <returns> <seealso cref="CompressionMethod"/> </returns>
		public virtual short getCompressionAlgorithm()
		{
			return compressionAlgorithm;
		}

		/// <returns> <seealso cref="PRFAlgorithm"/> </returns>
		public virtual int getPrfAlgorithm()
		{
			return prfAlgorithm;
		}

		public virtual int getVerifyDataLength()
		{
			return verifyDataLength;
		}

		public virtual byte[] getMasterSecret()
		{
			return masterSecret;
		}

		public virtual byte[] getClientRandom()
		{
			return clientRandom;
		}

		public virtual byte[] getServerRandom()
		{
			return serverRandom;
		}

		public virtual byte[] getSessionHash()
		{
			return sessionHash;
		}

		/// @deprecated Use <seealso cref="SecurityParameters#getPSKIdentity()"/> 
		public virtual byte[] getPskIdentity()
		{
			return pskIdentity;
		}

		public virtual byte[] getPSKIdentity()
		{
			return pskIdentity;
		}

		public virtual byte[] getSRPIdentity()
		{
			return srpIdentity;
		}

		public virtual bool isExtendedMasterSecret()
		{
			return extendedMasterSecret;
		}
	}

}