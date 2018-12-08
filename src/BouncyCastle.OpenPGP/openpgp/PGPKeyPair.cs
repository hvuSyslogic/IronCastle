namespace org.bouncycastle.openpgp
{
	/// <summary>
	/// General class to handle JCA key pairs and convert them into OpenPGP ones.
	/// <para>
	/// A word for the unwary, the KeyID for a OpenPGP public key is calculated from
	/// a hash that includes the time of creation, if you pass a different date to the 
	/// constructor below with the same public private key pair the KeyID will not be the
	/// same as for previous generations of the key, so ideally you only want to do 
	/// this once.
	/// </para>
	/// </summary>
	public class PGPKeyPair
	{
		protected internal PGPPublicKey pub;
		protected internal PGPPrivateKey priv;

		/// <summary>
		/// Create a key pair from a PGPPrivateKey and a PGPPublicKey.
		/// </summary>
		/// <param name="pub"> the public key </param>
		/// <param name="priv"> the private key </param>
		public PGPKeyPair(PGPPublicKey pub, PGPPrivateKey priv)
		{
			this.pub = pub;
			this.priv = priv;
		}

		public PGPKeyPair()
		{
		}

		/// <summary>
		/// Return the keyID associated with this key pair.
		/// </summary>
		/// <returns> keyID </returns>
		public virtual long getKeyID()
		{
			return pub.getKeyID();
		}

		public virtual PGPPublicKey getPublicKey()
		{
			return pub;
		}

		public virtual PGPPrivateKey getPrivateKey()
		{
			return priv;
		}
	}

}