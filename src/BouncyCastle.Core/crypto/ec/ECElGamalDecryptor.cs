using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.ec
{
				
	/// <summary>
	/// this does your basic decryption ElGamal style using EC
	/// </summary>
	public class ECElGamalDecryptor : ECDecryptor
	{
		private ECPrivateKeyParameters key;

		/// <summary>
		/// initialise the decryptor.
		/// </summary>
		/// <param name="param"> the necessary EC key parameters. </param>
		public virtual void init(CipherParameters param)
		{
			if (!(param is ECPrivateKeyParameters))
			{
				throw new IllegalArgumentException("ECPrivateKeyParameters are required for decryption.");
			}

			this.key = (ECPrivateKeyParameters)param;
		}

		/// <summary>
		/// Decrypt an EC pair producing the original EC point.
		/// </summary>
		/// <param name="pair"> the EC point pair to process. </param>
		/// <returns> the result of the Elgamal process. </returns>
		public virtual ECPoint decrypt(ECPair pair)
		{
			if (key == null)
			{
				throw new IllegalStateException("ECElGamalDecryptor not initialised");
			}

			ECCurve curve = key.getParameters().getCurve();
			ECPoint tmp = ECAlgorithms.cleanPoint(curve, pair.getX()).multiply(key.getD());

			return ECAlgorithms.cleanPoint(curve, pair.getY()).subtract(tmp).normalize();
		}
	}

}