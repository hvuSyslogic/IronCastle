using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters holder for public unified static/ephemeral agreement using Edwards Curves.
	/// </summary>
	public class XDHUPublicParameters : CipherParameters
	{
		private AsymmetricKeyParameter staticPublicKey;
		private AsymmetricKeyParameter ephemeralPublicKey;

		public XDHUPublicParameters(AsymmetricKeyParameter staticPublicKey, AsymmetricKeyParameter ephemeralPublicKey)
		{
			if (staticPublicKey == null)
			{
				throw new NullPointerException("staticPublicKey cannot be null");
			}
			if (!(staticPublicKey is X448PublicKeyParameters || staticPublicKey is X25519PublicKeyParameters))
			{
				throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
			}
			if (ephemeralPublicKey == null)
			{
				throw new NullPointerException("ephemeralPublicKey cannot be null");
			}
			if (!staticPublicKey.GetType().IsInstanceOfType(ephemeralPublicKey))
			{
				throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters");
			}

			this.staticPublicKey = staticPublicKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		public virtual AsymmetricKeyParameter getStaticPublicKey()
		{
			return staticPublicKey;
		}

		public virtual AsymmetricKeyParameter getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}