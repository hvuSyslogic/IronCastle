using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
	
	public class DESKeyGenerator : CipherKeyGenerator
	{
		/// <summary>
		/// initialise the key generator - if strength is set to zero
		/// the key generated will be 64 bits in size, otherwise
		/// strength can be 64 or 56 bits (if you don't count the parity bits).
		/// </summary>
		/// <param name="param"> the parameters to be used for key generation </param>
		public override void init(KeyGenerationParameters param)
		{
			base.init(param);

			if (strength == 0 || strength == (56 / 8))
			{
				strength = DESParameters.DES_KEY_LENGTH;
			}
			else if (strength != DESParameters.DES_KEY_LENGTH)
			{
				throw new IllegalArgumentException("DES key must be " + (DESParameters.DES_KEY_LENGTH * 8) + " bits long.");
			}
		}

		public override byte[] generateKey()
		{
			byte[] newKey = new byte[DESParameters.DES_KEY_LENGTH];

			do
			{
				random.nextBytes(newKey);

				DESParameters.setOddParity(newKey);
			} while (DESParameters.isWeakKey(newKey, 0));

			return newKey;
		}
	}

}