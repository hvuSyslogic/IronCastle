namespace org.bouncycastle.openpgp.@operator.jcajce
{


	/// <summary>
	/// A JCA PrivateKey carrier. Use this one if you're dealing with a hardware adapter.
	/// </summary>
	public class JcaPGPPrivateKey : PGPPrivateKey
	{
		private readonly PrivateKey privateKey;

		public JcaPGPPrivateKey(long keyID, PrivateKey privateKey) : base(keyID, null, null)
		{

			this.privateKey = privateKey;
		}

		public JcaPGPPrivateKey(PGPPublicKey pubKey, PrivateKey privateKey) : base(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), null)
		{

			this.privateKey = privateKey;
		}

		public virtual PrivateKey getPrivateKey()
		{
			return privateKey;
		}
	}

}