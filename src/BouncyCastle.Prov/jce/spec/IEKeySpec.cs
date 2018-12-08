namespace org.bouncycastle.jce.spec
{

	using IESKey = org.bouncycastle.jce.interfaces.IESKey;

	/// <summary>
	/// key pair for use with an integrated encryptor - together
	/// they provide what's required to generate the message.
	/// </summary>
	public class IEKeySpec : KeySpec, IESKey
	{
		private PublicKey pubKey;
		private PrivateKey privKey;

		/// <param name="privKey"> our private key. </param>
		/// <param name="pubKey"> the public key of the sender/recipient. </param>
		public IEKeySpec(PrivateKey privKey, PublicKey pubKey)
		{
			this.privKey = privKey;
			this.pubKey = pubKey;
		}

		/// <summary>
		/// return the intended recipient's/sender's public key.
		/// </summary>
		public virtual PublicKey getPublic()
		{
			return pubKey;
		}

		/// <summary>
		/// return the local private key.
		/// </summary>
		public virtual PrivateKey getPrivate()
		{
			return privKey;
		}

		/// <summary>
		/// return "IES"
		/// </summary>
		public virtual string getAlgorithm()
		{
			return "IES";
		}

		/// <summary>
		/// return null
		/// </summary>
		public virtual string getFormat()
		{
			return null;
		}

		/// <summary>
		/// returns null
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return null;
		}
	}

}