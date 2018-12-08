using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class DHMQVPublicParameters : CipherParameters
	{
		private DHPublicKeyParameters staticPublicKey;
		private DHPublicKeyParameters ephemeralPublicKey;

		public DHMQVPublicParameters(DHPublicKeyParameters staticPublicKey, DHPublicKeyParameters ephemeralPublicKey)
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

		public virtual DHPublicKeyParameters getStaticPublicKey()
		{
			return staticPublicKey;
		}

		public virtual DHPublicKeyParameters getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}