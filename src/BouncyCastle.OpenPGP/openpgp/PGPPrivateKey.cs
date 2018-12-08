namespace org.bouncycastle.openpgp
{
	using BCPGKey = org.bouncycastle.bcpg.BCPGKey;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;

	/// <summary>
	/// general class to contain a private key for use with other openPGP
	/// objects.
	/// </summary>
	public class PGPPrivateKey
	{
		private long keyID;
		private PublicKeyPacket publicKeyPacket;
		private BCPGKey privateKeyDataPacket;

		/// <summary>
		/// Base constructor.
		/// 
		/// Create a PGPPrivateKey from a keyID and the associated public/private data packets needed
		/// to fully describe it.
		/// </summary>
		/// <param name="keyID"> keyID associated with the public key. </param>
		/// <param name="publicKeyPacket"> the public key data packet to be associated with this private key. </param>
		/// <param name="privateKeyDataPacket"> the private key data packet to be associate with this private key. </param>
		public PGPPrivateKey(long keyID, PublicKeyPacket publicKeyPacket, BCPGKey privateKeyDataPacket)
		{
			this.keyID = keyID;
			this.publicKeyPacket = publicKeyPacket;
			this.privateKeyDataPacket = privateKeyDataPacket;
		}

		/// <summary>
		/// Return the keyID associated with the contained private key.
		/// </summary>
		/// <returns> long </returns>
		public virtual long getKeyID()
		{
			return keyID;
		}

		/// <summary>
		/// Return the public key packet associated with this private key, if available.
		/// </summary>
		/// <returns> associated public key packet, null otherwise. </returns>
		public virtual PublicKeyPacket getPublicKeyPacket()
		{
			return publicKeyPacket;
		}

		/// <summary>
		/// Return the private key packet associated with this private key, if available.
		/// </summary>
		/// <returns> associated private key packet, null otherwise. </returns>
		public virtual BCPGKey getPrivateKeyDataPacket()
		{
			return privateKeyDataPacket;
		}
	}

}