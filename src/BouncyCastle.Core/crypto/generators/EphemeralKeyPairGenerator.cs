namespace org.bouncycastle.crypto.generators
{

	public class EphemeralKeyPairGenerator
	{
		private AsymmetricCipherKeyPairGenerator gen;
		private KeyEncoder keyEncoder;

		public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator gen, KeyEncoder keyEncoder)
		{
			this.gen = gen;
			this.keyEncoder = keyEncoder;
		}

		public virtual EphemeralKeyPair generate()
		{
			AsymmetricCipherKeyPair eph = gen.generateKeyPair();

			// Encode the ephemeral public key
			 return new EphemeralKeyPair(eph, keyEncoder);
		}
	}

}