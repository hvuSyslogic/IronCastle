using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters holder for public unified static/ephemeral agreement as described in NIST SP 800-56A using EC DH/CDH.
	/// </summary>
	public class ECDHUPublicParameters : CipherParameters
	{
		private ECPublicKeyParameters staticPublicKey;
		private ECPublicKeyParameters ephemeralPublicKey;

		public ECDHUPublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
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
				throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters");
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