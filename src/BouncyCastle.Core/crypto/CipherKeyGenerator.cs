using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// The base class for symmetric, or secret, cipher key generators.
	/// </summary>
	public class CipherKeyGenerator
	{
		protected internal SecureRandom random;
		protected internal int strength;

		/// <summary>
		/// initialise the key generator.
		/// </summary>
		/// <param name="param"> the parameters to be used for key generation </param>
		public virtual void init(KeyGenerationParameters param)
		{
			this.random = param.getRandom();
			this.strength = (param.getStrength() + 7) / 8;
		}

		/// <summary>
		/// generate a secret key.
		/// </summary>
		/// <returns> a byte array containing the key value. </returns>
		public virtual byte[] generateKey()
		{
			byte[] key = new byte[strength];

			random.nextBytes(key);

			return key;
		}
	}

}