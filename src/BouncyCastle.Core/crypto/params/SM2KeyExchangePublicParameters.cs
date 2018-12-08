using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Public parameters for an SM2 key exchange. In this case the ephemeralPublicKey provides the random point used in the algorithm.
	/// </summary>
	public class SM2KeyExchangePublicParameters : CipherParameters
	{
		private readonly ECPublicKeyParameters staticPublicKey;
		private readonly ECPublicKeyParameters ephemeralPublicKey;

		public SM2KeyExchangePublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
		{
			if (staticPublicKey == null)
			{
				throw new NullPointerException("staticPublicKey cannot be null");
			}
			if (ephemeralPublicKey == null)
			{
				throw new NullPointerException("ephemeralPublicKey cannot be null");
			}
			if (!staticPublicKey.getParameters().Equals(ephemeralPublicKey.getParameters()))
			{
				throw new IllegalArgumentException("Static and ephemeral public keys have different domain parameters");
			}

			this.staticPublicKey = staticPublicKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		public virtual ECPublicKeyParameters getStaticPublicKey()
		{
			return staticPublicKey;
		}

		public virtual ECPublicKeyParameters getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}