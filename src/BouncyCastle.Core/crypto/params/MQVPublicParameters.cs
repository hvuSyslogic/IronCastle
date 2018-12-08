using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class MQVPublicParameters : CipherParameters
	{
		private ECPublicKeyParameters staticPublicKey;
		private ECPublicKeyParameters ephemeralPublicKey;

		public MQVPublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
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