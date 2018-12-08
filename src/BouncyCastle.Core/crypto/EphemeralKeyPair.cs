namespace org.bouncycastle.crypto
{
	public class EphemeralKeyPair
	{
		private AsymmetricCipherKeyPair keyPair;
		private KeyEncoder publicKeyEncoder;

		public EphemeralKeyPair(AsymmetricCipherKeyPair keyPair, KeyEncoder publicKeyEncoder)
		{
			this.keyPair = keyPair;
			this.publicKeyEncoder = publicKeyEncoder;
		}

		public virtual AsymmetricCipherKeyPair getKeyPair()
		{
			return keyPair;
		}

		public virtual byte[] getEncodedPublicKey()
		{
			return publicKeyEncoder.getEncoded(keyPair.getPublic());
		}
	}

}